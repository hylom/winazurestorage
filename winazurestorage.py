#!/usr/bin/env python
# encoding: utf-8
"""
Python wrapper around Windows Azure storage
Sriram Krishnan <sriramk@microsoft.com>
Steve Marx <steve.marx@microsoft.com>
"""

import base64
import hmac
import hashlib
import time
import sys
import os
from xml.dom import minidom #TODO: Use a faster way of processing XML
import re
from urllib2 import Request, urlopen, URLError
from urllib import urlencode, quote
from urlparse import urlsplit, parse_qs
from datetime import datetime, timedelta

import locale # dirty hack for locale changing

DEVSTORE_ACCOUNT = "devstoreaccount1"
DEVSTORE_SECRET_KEY = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="

DEVSTORE_BLOB_HOST = "127.0.0.1:10000"
DEVSTORE_QUEUE_HOST = "127.0.0.1:10001"
DEVSTORE_TABLE_HOST = "127.0.0.1:10002"

CLOUD_BLOB_HOST = "blob.core.windows.net"
CLOUD_TABLE_HOST = "table.core.windows.net"
CLOUD_QUEUE_HOST = "queue.core.windows.net"

PREFIX_PROPERTIES = "x-ms-prop-"
PREFIX_METADATA = "x-ms-meta-"
PREFIX_STORAGE_HEADER = "x-ms-"

NEW_LINE = "\x0A"

DEBUG = False

TIME_FORMAT ="%a, %d %b %Y %H:%M:%S %Z"

def parse_edm_datetime(input):
    d = datetime.strptime(input[:input.find('.')], "%Y-%m-%dT%H:%M:%S")
    if input.find('.') != -1:
        d += timedelta(0, 0, int(round(float(input[input.index('.'):-1])*1000000)))
    return d

def parse_edm_int32(input):
    return int(input)

def parse_edm_int64(input):
    return long(input)

def parse_edm_double(input):
    return float(input)

def parse_edm_boolean(input):
    return input.lower() == "true"

class SharedKeyCredentials(object):
    def __init__(self, account_name, account_key, use_path_style_uris = None):
        self._account = account_name
        self._key = base64.decodestring(account_key)

    def _sign_request_impl(self, request, for_tables = False,  use_path_style_uris = None):
        (scheme, host, path, query, fragment) = urlsplit(request.get_full_url())
        if use_path_style_uris:
            path = path[path.index('/'):]

        canonicalized_resource = "/" + self._account + path

        if not for_tables:
            q = parse_qs(query)
            if len(q.keys()) > 0:
                canonicalized_resource +=''.join(["\n%s:%s" % (k, ','.join(sorted(q[k]))) for k in sorted(q.keys())])

        if use_path_style_uris is None:
            use_path_style_uris = re.match('^[\d.:]+$', host) is not None

        request.add_header(PREFIX_STORAGE_HEADER + 'version', '2011-08-18')
        locale.setlocale(locale.LC_ALL, "C") # dirty hack for locale changing
        request.add_header(PREFIX_STORAGE_HEADER + 'date', time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())) #RFC 1123

        if for_tables:
            request.add_header('Date', request.get_header((PREFIX_STORAGE_HEADER + 'date').capitalize()))
            request.add_header('DataServiceVersion', '1.0;NetFx')
            request.add_header('MaxDataServiceVersion', '1.0;NetFx')

        canonicalized_headers = NEW_LINE.join(('%s:%s' % (k.lower(), request.get_header(k).strip()) for k in sorted(request.headers.keys(), lambda x,y: cmp(x.lower(), y.lower())) if k.lower().startswith(PREFIX_STORAGE_HEADER)))

        string_to_sign = request.get_method().upper() + NEW_LINE # verb
        if not for_tables:
            string_to_sign += (request.get_header('Content-encoding') or '') + NEW_LINE
            string_to_sign += (request.get_header('Content-language') or '') + NEW_LINE
            string_to_sign += str(request.get_header('Content-length') or '') + NEW_LINE
                
        string_to_sign += (request.get_header('Content-md5') or '') + NEW_LINE
        string_to_sign += (request.get_header('Content-type') or '') + NEW_LINE
        string_to_sign += (request.get_header('Date') or '') + NEW_LINE
        if not for_tables:
            string_to_sign += (request.get_header('If-modified-since') or '') + NEW_LINE
            string_to_sign += (request.get_header('If-match') or '') + NEW_LINE
            string_to_sign += (request.get_header('If-none-match') or '') + NEW_LINE
            string_to_sign += (request.get_header('If-unmodified-since') or '') + NEW_LINE
            string_to_sign += (request.get_header('Range') or '') + NEW_LINE
        if not for_tables:
            string_to_sign += canonicalized_headers + NEW_LINE
        string_to_sign += canonicalized_resource

        request.add_header('Authorization', 'SharedKey ' + self._account + ':' + base64.encodestring(hmac.new(self._key, unicode(string_to_sign).encode("utf-8"), hashlib.sha256).digest()).strip())
        return request

    def sign_request(self, request, use_path_style_uris = None):
        return self._sign_request_impl(request, use_path_style_uris)

    def sign_table_request(self, request, use_path_style_uris = None):
        return self._sign_request_impl(request, for_tables = True, use_path_style_uris = use_path_style_uris)

class RequestWithMethod(Request):
    '''Subclass urllib2.Request to add the capability of using methods other than GET and POST.
       Thanks to http://benjamin.smedbergs.us/blog/2008-10-21/putting-and-deleteing-in-python-urllib2/'''
    def __init__(self, method, *args, **kwargs):
        self._method = method
        Request.__init__(self, *args, **kwargs)

    def get_method(self):
        return self._method

class Table(object):
    def __init__(self, url, name):
        self.url = url
        self.name = name

class Storage(object):
    def __init__(self, host, account_name, secret_key, use_path_style_uris):
        self._host = host
        self._account = account_name
        self._key = secret_key
        if use_path_style_uris is None:
            use_path_style_uris = re.match(r'^[^:]*[\d:]+$', self._host)
        self._use_path_style_uris = use_path_style_uris
        self._credentials = SharedKeyCredentials(self._account, self._key)

    def get_base_url(self):
        if self._use_path_style_uris:
            return "http://%s/%s" % (self._host, self._account)
        else:
            return "http://%s.%s" % (self._account, self._host)

class TableEntityException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class TableEntity(object):
    "Table Entity"
    def __init__(self, partition_key="", row_key="", props={}):
        self.partition_key = partition_key
        self.row_key = row_key
        self.properties = props

#    class Binary(object):
#        pass

#    class Guid(object):
#        pass

    class Boolean(int):
        def __str__(self):
            if self:
                return "true"
            else:
                return "false"

    def __repr__(self):
        props = ",".join([ k + ":" + str(self.properties[k]) for k in self.properties])
        return ",".join((self.partition_key, self.row_key, props))

    def add_property(self, key, value):
        self.properties[key] = value

    def to_insert_xml(self):
        contents = [self._make_property_node(propname, self.properties[propname]) for propname in self.properties]
        contents_str = "\n".join(contents)
        now_str = datetime.utcnow().isoformat() + "Z"
        xml = """<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<entry xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata" xmlns="http://www.w3.org/2005/Atom">
  <title />
  <author>
    <name />
  </author>
  <id />
  <content type="application/xml">
    <m:properties>
%(contents)s
      <d:PartitionKey>%(partition_key)s</d:PartitionKey>
      <d:RowKey>%(row_key)s</d:RowKey>
      <d:Timestamp m:type="Edm.DateTime">0001-01-01T00:00:00</d:Timestamp>
    </m:properties>
  </content>
</entry>
""" % dict(contents=contents_str, now=now_str, partition_key=self.partition_key, row_key=self.row_key)
        if isinstance(xml, unicode):
            xml = xml.encode('utf-8')
        return xml

    def to_update_xml(self):
        contents = [self._make_property_node(propname, self.properties[propname]) for propname in self.properties]
        contents_str = "\n".join(contents)
        now_str = datetime.utcnow().isoformat() + "Z"
        xml = """<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<entry xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata" xmlns="http://www.w3.org/2005/Atom">
  <title />
  <updated>%(now)s</updated>
  <author>
    <name />
  </author>
  <id />
  <content type="application/xml">
    <m:properties>
%(contents)s
      <d:PartitionKey>%(partition_key)s</d:PartitionKey>
      <d:RowKey>%(row_key)s</d:RowKey>
      <d:Timestamp m:type="Edm.DateTime">0001-01-01T00:00:00</d:Timestamp>
    </m:properties>
  </content>
</entry>
""" % dict(contents=contents_str, now=now_str, partition_key=self.partition_key, row_key=self.row_key)
        if isinstance(xml, unicode):
            xml = xml.encode('utf-8')
        return xml
    
    def _make_property_node(self, name, value):
        type = ""
        string_repr = ""
#        if isinstance(value, TableEntity.Binary):
#            type = "Edm.Binary"
#            string_repr = str(TableEntity.Binary(value))
        if isinstance(value, bool):
            type = "Edm.Boolean"
            string_repr = str(TableEntity.Boolean(value))
        elif isinstance(value, datetime):
            type = "Edm.DateTime"
            string_repr = value.isoformat()
        elif isinstance(value, float):
            type = "Edm.Double"
            string_repr = str(value)
#        elif isinstance(value, TableEntity.Guid):
#            type = "Edm.Guid"
#            string_repr = str(TableEntity.Boolean(value))
        elif isinstance(value, long):
            type = "Edm.Int64"
            string_repr = str(value)
        elif isinstance(value, int):
            type = "Edm.Int32"
            string_repr = str(value)
        elif isinstance(value, str):
            type = "Edm.String"
            string_repr = value
        elif isinstance(value, unicode):
            type = "Edm.String"
            string_repr = value
        if type is not "":
            prop_element = """<d:%(name)s m:type="%(type)s">%(value)s</d:%(name)s>"""
            return prop_element % dict(name=name, type=type, value=string_repr)
        else:
            raise TableEntityException("Unexpected property: %s" % (value,))

class QueueMessage(): pass

class QueueStorage(Storage):
    def __init__(self, host = DEVSTORE_QUEUE_HOST, account_name = DEVSTORE_ACCOUNT, secret_key = DEVSTORE_SECRET_KEY, use_path_style_uris = None):
        super(QueueStorage, self).__init__(host, account_name, secret_key, use_path_style_uris)

    def create_queue(self, name):
        req = RequestWithMethod("PUT", "%s/%s" % (self.get_base_url(), name))
        req.add_header("Content-Length", "0")
        self._credentials.sign_request(req)
        try:
            response = urlopen(req)
            return response.code
        except URLError, e:
            return e.code

    def delete_queue(self, name):
        req = RequestWithMethod("DELETE", "%s/%s" % (self.get_base_url(), name))
        self._credentials.sign_request(req)
        try:
            response = urlopen(req)
            return response.code
        except URLError, e:
            return e.code
            
    def put_message(self, queue_name, payload):
        data = "<QueueMessage><MessageText>%s</MessageText></QueueMessage>" % base64.encodestring(payload)
        req = RequestWithMethod("POST", "%s/%s/messages" % (self.get_base_url(), queue_name), data=data)
        req.add_header("Content-Type", "application/xml")
        req.add_header("Content-Length", len(data))
        self._credentials.sign_request(req)
        try:
            response = urlopen(req)
            return response.code
        except URLError, e:
            return e.code

    def get_message(self, queue_name):
        req = Request("%s/%s/messages" % (self.get_base_url(), queue_name))
        self._credentials.sign_request(req)
        response = urlopen(req)
        dom = minidom.parseString(response.read())
        messages = dom.getElementsByTagName("QueueMessage")
        result = None
        if len(messages) == 1:
            message = messages[0]
            result = QueueMessage()
            result.id = message.getElementsByTagName("MessageId")[0].firstChild.data
            result.pop_receipt = message.getElementsByTagName("PopReceipt")[0].firstChild.data
            result.text = base64.decodestring(message.getElementsByTagName("MessageText")[0].firstChild.data)
        return result

    def delete_message(self, queue_name, message):
        id = message.id
        pop_receipt = message.pop_receipt
        req = RequestWithMethod("DELETE", "%s/%s/messages/%s?popreceipt=%s" % (self.get_base_url(), queue_name, id, pop_receipt))
        self._credentials.sign_request(req)
        try:
            response = urlopen(req)
            return response.code
        except URLError, e:
            return e.code

class TableStorage(Storage):
    '''Due to local development storage not supporting SharedKey authentication, this class
       will only work against cloud storage.'''
    def __init__(self, host, account_name, secret_key, use_path_style_uris = None):
        super(TableStorage, self).__init__(host, account_name, secret_key, use_path_style_uris)

    def create_table(self, name):
        data = """<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<entry xmlns:d="http://schemas.microsoft.com/ado/2007/08/dataservices" xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata" xmlns="http://www.w3.org/2005/Atom">
  <title />
  <updated>%s</updated>
  <author>
    <name />
  </author>
  <id />
  <content type="application/xml">
    <m:properties>
      <d:TableName>%s</d:TableName>
    </m:properties>
  </content>
</entry>""" % (time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()), name)
        req = RequestWithMethod("POST", "%s/Tables" % self.get_base_url(), data=data)
        req.add_header("Content-Length", "%d" % len(data))
        req.add_header("Content-Type", "application/atom+xml")
        self._credentials.sign_table_request(req)
        try:
            response = urlopen(req)
            return response.code
        except URLError, e:
            return e.code

    def delete_table(self, name):
        req = RequestWithMethod("DELETE", "%s/Tables('%s')" % (self.get_base_url(), name))
        self._credentials.sign_table_request(req)
        try:
            response = urlopen(req)
            return response.code
        except URLError, e:
            return e.code

    def list_tables(self):
        req = Request("%s/Tables" % self.get_base_url())
        self._credentials.sign_table_request(req)
        response = urlopen(req)

        dom = minidom.parseString(response.read())
        
        entries = dom.getElementsByTagName("entry")
        for entry in entries:
            table_url = entry.getElementsByTagName("id")[0].firstChild.data
            table_name = entry.getElementsByTagName("content")[0].getElementsByTagName("m:properties")[0].getElementsByTagName("d:TableName")[0].firstChild.data
            yield Table(table_url, table_name)
        dom.unlink()

    def get_entity(self, table_name, partition_key, row_key):
        dom = minidom.parseString(urlopen(self._credentials.sign_table_request(Request("%s/%s(PartitionKey='%s',RowKey='%s')" % (self.get_base_url(), table_name, partition_key, row_key)))).read())
        entity = self._parse_entity(dom.getElementsByTagName("entry")[0])
        dom.unlink()
        return entity

    def _parse_entity(self, entry):
        entity = TableEntity()
        for property in (p for p in entry.getElementsByTagName("m:properties")[0].childNodes if p.nodeType == minidom.Node.ELEMENT_NODE):
            key = property.tagName[2:]
            if property.hasAttribute('m:type'):
                t = property.getAttribute('m:type')
                if t.lower() == 'edm.datetime': value = parse_edm_datetime(property.firstChild.data)
                elif t.lower() == 'edm.int32': value = parse_edm_int32(property.firstChild.data)
                elif t.lower() == 'edm.int64': value = parse_edm_int64(property.firstChild.data)
                elif t.lower() == 'edm.boolean': value = parse_edm_boolean(property.firstChild.data)
                elif t.lower() == 'edm.double': value = parse_edm_double(property.firstChild.data)
                else: raise Exception(t.lower())
            else: value = property.firstChild is not None and property.firstChild.data or None
            setattr(entity, key, value)
        return entity

    def get_all(self, table_name):
        dom = minidom.parseString(urlopen(self._credentials.sign_table_request(Request("%s/%s" % (self.get_base_url(), table_name)))).read())
        entries = dom.getElementsByTagName("entry")
        entities = []
        for entry in entries:
            entities.append(self._parse_entity(entry))
        dom.unlink()
        return entities

    def insert_entity(self, table_name, entity):
        data = entity.to_insert_xml()
        url = "%s/%s" % (self.get_base_url(), table_name)
        req = RequestWithMethod("POST", url, data=data)
        req.add_header("Content-Length", "%d" % len(data))
        req.add_header("Content-Type", "application/atom+xml")
        self._credentials.sign_table_request(req)
        try:
            response = urlopen(req)
            return response.code
        except URLError, e:
            return e.code

    def update_entity(self, table_name, partition_key, row_key, entity):
        data = entity.to_update_xml()
        url = """%s/%s(PartitionKey='%s',RowKey='%s')""" % (self.get_base_url(), table_name, partition_key, row_key)
        if isinstance(url, unicode):
            url = url.encode('utf-8')

        req = RequestWithMethod("PUT", url, data=data)
        req.add_header("Content-Length", "%d" % len(data))
        req.add_header("Content-Type", "application/atom+xml")
        self._credentials.sign_table_request(req)
        try:
            response = urlopen(req)
            return response.code
        except URLError, e:
            return e.code

    def merge_entity(self, table_name, partition_key, row_key, entity):
        data = entity.to_update_xml()
        url = """%s/%s(PartitionKey='%s',RowKey='%s')""" % (self.get_base_url(), table_name, partition_key, row_key)
        if isinstance(url, unicode):
            url = url.encode('utf-8')
        req = RequestWithMethod("MERGE", url, data=data)
        req.add_header("Content-Length", "%d" % len(data))
        req.add_header("Content-Type", "application/atom+xml")
        self._credentials.sign_table_request(req)
        try:
            response = urlopen(req)
            return response.code
        except URLError, e:
            return e.code

    def delete_entity(self, table_name, partition_key, row_key, condition="*"):
        data = ""
        url = """%s/%s(PartitionKey='%s',RowKey='%s')""" % (self.get_base_url(), table_name, partition_key, row_key)
        if isinstance(url, unicode):
            url = url.encode('utf-8')
        req = RequestWithMethod("DELETE", url, data)
        req.add_header("Content-Length", "%d" % len(data))
        req.add_header("Content-Type", "application/atom+xml")
        req.add_header("If-Match", condition)
        self._credentials.sign_table_request(req)
        try:
            response = urlopen(req)
            return response.code
        except URLError, e:
            return e.code

    def query_entity(self, table_name, filter):
        quoted_filter = quote(filter)
        url = """%s/%s()?$filter=%s""" % (self.get_base_url(), table_name, quoted_filter)
        if isinstance(url, unicode):
            url = url.encode('utf-8')
        req = RequestWithMethod("GET", url)
        self._credentials.sign_table_request(req)
        try:
            resp = urlopen(req)
        except URLError, e:
            return e.code

        dom = minidom.parseString(resp.read())
        entries = dom.getElementsByTagName("entry")
        entities = []
        for entry in entries:
            entities.append(self._parse_entity(entry))
        dom.unlink()
        return entities

    def top_entity(self, table_name, size):
        url = """%s/%s()?$top=%s""" % (self.get_base_url(), table_name, size)
        if isinstance(url, unicode):
            url = url.encode('utf-8')
        req = RequestWithMethod("GET", url)
        self._credentials.sign_table_request(req)

        try:
            resp = urlopen(req)
        except URLError, e:
            return e.code

        dom = minidom.parseString(resp.read())
        entries = dom.getElementsByTagName("entry")
        entities = []
        for entry in entries:
            entities.append(self._parse_entity(entry))
        dom.unlink()
        return entities

class BlobStorage(Storage):
    def __init__(self, host = DEVSTORE_BLOB_HOST, account_name = DEVSTORE_ACCOUNT, secret_key = DEVSTORE_SECRET_KEY, use_path_style_uris = None):
        super(BlobStorage, self).__init__(host, account_name, secret_key, use_path_style_uris)

    def create_container(self, container_name, is_public = False):
        req = RequestWithMethod("PUT", "%s/%s?restype=container" % (self.get_base_url(), container_name))
        req.add_header("Content-Length", "0")
        if is_public: req.add_header(PREFIX_PROPERTIES + "publicaccess", "true")
        self._credentials.sign_request(req)
        try:
            response = urlopen(req)
            return response.code
        except URLError, e:
            return e.code

    def delete_container(self, container_name):
        req = RequestWithMethod("DELETE", "%s/%s?restype=container" % (self.get_base_url(), container_name))
        self._credentials.sign_request(req)
        try:
            response = urlopen(req)
            return response.code
        except URLError, e:
            return e.code

    def list_containers(self):
        req = Request("%s/?comp=list" % self.get_base_url())
        self._credentials.sign_request(req)
        dom = minidom.parseString(urlopen(req).read())
        containers = dom.getElementsByTagName("Container")
        for container in containers:
            container_name = container.getElementsByTagName("Name")[0].firstChild.data
            etag = container.getElementsByTagName("Etag")[0].firstChild.data
            last_modified = time.strptime(container.getElementsByTagName("LastModified")[0].firstChild.data, TIME_FORMAT)
            yield (container_name, etag, last_modified)
        
        dom.unlink() #Docs say to do this to force GC. Ugh.

    def put_blob(self, container_name, blob_name, data, content_type = "", metadata = {}):
        req = RequestWithMethod("PUT", "%s/%s/%s" % (self.get_base_url(), container_name, blob_name), data=data)
        req.add_header("Content-Length", "%d" % len(data))
        req.add_header('x-ms-blob-type', 'BlockBlob')
        for key, value in metadata.items():
            req.add_header("x-ms-meta-%s" % key, value)
        req.add_header("Content-Type", content_type)
        self._credentials.sign_request(req)
        try:
            response = urlopen(req)
            return response.code
        except URLError, e:
            return e.code

    def delete_blob(self, container_name, blob_name):
        req = RequestWithMethod("DELETE", "%s/%s/%s" % (self.get_base_url(), container_name, blob_name))
        self._credentials.sign_request(req)
        urlopen(req)

    def get_blob(self, container_name, blob_name):
        req = Request("%s/%s/%s" % (self.get_base_url(), container_name, blob_name))
        self._credentials.sign_request(req)
        return urlopen(req).read()

    def get_blob_with_metadata(self, container_name, blob_name):
        req = Request("%s/%s/%s" % (self.get_base_url(), container_name, blob_name))
        self._credentials.sign_request(req)
        response = urlopen(req)
        metadata = {}
        for key, value in response.info().items():
            if key.startswith('x-ms-meta-'):
                metadata[key[len('x-ms-meta-'):]] = value
        return metadata, response.read()

    def blob_exists(self, container_name, blob_name):
        req = RequestWithMethod("HEAD", "%s/%s/%s" % (self.get_base_url(), container_name, blob_name))
        self._credentials.sign_request(req)
        try:
            urlopen(req)
            return True
        except:
            return False
		
    def list_blobs(self, container_name, blob_prefix=None):
        marker = None
        while True:
            url = "%s/%s?restype=container&comp=list" % (self.get_base_url(), container_name)
            if not blob_prefix is None: url += "&%s" % urlencode({"prefix": blob_prefix})
            if not marker is None: url += "&marker=%s" % marker
            req = Request(url)
            self._credentials.sign_request(req)
            dom = minidom.parseString(urlopen(req).read())
            blobs = dom.getElementsByTagName("Blob")
            for blob in blobs:
                blob_name = blob.getElementsByTagName("Name")[0].firstChild.data
                etag = blob.getElementsByTagName("Etag")[0].firstChild.data
                last_modified = time.strptime(blob.getElementsByTagName("LastModified")[0].firstChild.data, TIME_FORMAT)
                yield (blob_name, etag, last_modified)
            try: marker = dom.getElementsByTagName("NextMarker")[0].firstChild.data
            except: marker = None
            if marker is None: break

    def put_block(self, container_name, blob_name, block_id, data):
        encoded_block_id = urlencode({"comp": "block", "blockid": block_id})
        req = RequestWithMethod("PUT", "%s/%s/%s?%s" % (self.get_base_url(), container_name, blob_name, encoded_block_id), data=data)
        req.add_header("Content-Type", "")
        req.add_header("Content-Length", "%d" % len(data))
        self._credentials.sign_request(req)
        try:
            response = urlopen(req)
            return response.code
        except URLError, e:
            return e.code

def main():
    pass

if __name__ == '__main__':
    main()

