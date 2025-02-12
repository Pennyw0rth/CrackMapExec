# SPDX-License-Identifier: GPL-2.0+

import struct
import uuid

from datetime import datetime

class Substitution:
    def __init__(self, buf, offset):
        (sub_token, sub_id, sub_type) = struct.unpack_from("<BHB", buf, offset)
        self.length = 4

        self._id = sub_id
        self._type = sub_type
        self._optional = sub_token == 0x0e

    def xml(self, template=None):
        value = template.values[self._id]
        if value.type == 0x0:
            return None if self._optional else ""
        if self._type == 0x1:
            return value.data.decode("utf16")
        elif self._type == 0x4:
            return str(struct.unpack("<B", value.data)[0])
        elif self._type == 0x6:
            return str(struct.unpack("<H", value.data)[0])
        elif self._type == 0x8:
            return str(struct.unpack("<I", value.data)[0])
        elif self._type == 0xa:
            return str(struct.unpack("<Q", value.data)[0])
        elif self._type == 0x11:
            # see http://integriography.wordpress.com/2010/01/16/using-phython-to-parse-and-present-windows-64-bit-timestamps/
            return datetime.utcfromtimestamp(struct.unpack("<Q", value.data)[0] / 1e7 - 11644473600).isoformat()
        elif self._type == 0x13:
            # see http://www.gossamer-threads.com/lists/apache/bugs/386930
            revision, number_of_sub_ids = struct.unpack_from("<BB", value.data)
            iav = struct.unpack_from(">Q", value.data, 2)[0]
            sub_ids = [struct.unpack("<I", value.data[8 + 4 * i:12 + 4 * i])[0] for i in range(number_of_sub_ids)]
            return "S-{}-{}-{}".format(revision, iav, "-".join([str(sub_id) for sub_id in sub_ids]))
        elif self._type == 0x15 or self._type == 0x10:
            return value.data.hex()
        elif self._type == 0x21:
            return value.template.xml()
        elif self._type == 0xf:
            return str(uuid.UUID(bytes_le=value.data))
        else:
            print("Unknown value type", hex(value.type))

class Value:
    def __init__(self, buf, offset):
        token, string_type, length = struct.unpack_from("<BBH", buf, offset)
        self._val = buf[offset + 4:offset + 4 + length * 2].decode("utf16")

        self.length = 4 + length * 2

    def xml(self, template=None):
        return self._val

class Attribute:
    def __init__(self, buf, offset):
        struct.unpack_from("<B", buf, offset)
        self._name = Name(buf, offset + 1)

        (next_token) = struct.unpack_from("<B", buf, offset + 1 + self._name.length)
        if next_token[0] == 0x05 or next_token == 0x45:
            self._value = Value(buf, offset + 1 + self._name.length)
        elif next_token[0] == 0x0e:
            self._value = Substitution(buf, offset + 1 + self._name.length)
        else:
            print("Unknown attribute next_token", hex(next_token[0]), hex(offset + 1 + self._name.length))

        self.length = 1 + self._name.length + self._value.length

    def xml(self, template=None):
        val = self._value.xml(template)
        return None if val is None else f'{self._name.val}="{val}"'

class Name:
    def __init__(self, buf, offset):
        hashs, length = struct.unpack_from("<HH", buf, offset)

        self.val = buf[offset + 4:offset + 4 + length * 2].decode("utf16")
        self.length = 4 + (length + 1) * 2

class Element:
    def __init__(self, buf, offset):
        token, dependency_id, length = struct.unpack_from("<BHI", buf, offset)

        self._name = Name(buf, offset + 7)
        self._dependency = dependency_id

        ofs = offset + 7 + self._name.length
        if token == 0x41:
            struct.unpack_from("<I", buf, ofs)
            ofs += 4

        self._children = []
        self._attributes = []

        while True:
            next_token = buf[ofs]
            if next_token == 0x06 or next_token == 0x46:
                attr = Attribute(buf, ofs)
                self._attributes.append(attr)
                ofs += attr.length
            elif next_token == 0x02:
                self._empty = False
                ofs += 1
                while True:
                    next_token = buf[ofs]
                    if next_token == 0x01 or next_token == 0x41:
                        element = Element(buf, ofs)
                    elif next_token == 0x04:
                        ofs += 1
                        break
                    elif next_token == 0x05:
                        element = Value(buf, ofs)
                    elif next_token == 0x0e or next_token == 0x0d:
                        element = Substitution(buf, ofs)
                    else:
                        print("Unknown intern next_token", hex(next_token), hex(ofs))
                        break

                    self._children.append(element)
                    ofs += element.length

                break
            elif next_token == 0x03:
                self._empty = True
                ofs += 1
                break
            else:
                print("Unknown element next_token", hex(next_token), hex(ofs))
                break

        self.length = ofs - offset

    def xml(self, template=None):
        if self._dependency != 0xFFFF and template.values[self._dependency].type == 0x00:
            return ""

        attrs = filter(lambda x: x is not None, (x.xml(template) for x in self._attributes))
        
        attrs = " ".join(attrs)
        if len(attrs) > 0:
            attrs = " " + attrs
            
        if self._empty:
            return f"<{self._name.val}{attrs}/>"
        else:
            children = (x.xml(template) for x in self._children)
            return "<{}{}>{}</{}>".format(self._name.val, attrs, "".join(children), self._name.val)

class ValueSpec:
    def __init__(self, buf, offset, value_offset):
        self.length, self.type, value_eof = struct.unpack_from("<HBB", buf, offset)
        self.data = buf[value_offset:value_offset + self.length]

        if self.type == 0x21:
            self.template = BinXML(buf, value_offset)

class TemplateInstance:
    def __init__(self, buf, offset):
        token, unknown0, guid, length, next_token = struct.unpack_from("<BB16sIB", buf, offset)
        if next_token == 0x0F:
            self._xml = BinXML(buf, offset + 0x16)
            eof, num_values = struct.unpack_from("<BI", buf, offset + 22 + self._xml.length)
            values_length = 0
            self.values = []
            for x in range(num_values):
                value = ValueSpec(buf, offset + 22 + self._xml.length + 5 + x * 4, offset + 22 + self._xml.length + 5 + num_values * 4 + values_length)
                self.values.append(value)
                values_length += value.length

            self.length = 22 + self._xml.length + 5 + num_values * 4 + values_length
        else:
            print("Unknown template token", hex(next_token))

    def xml(self, template=None):
        return self._xml.xml(self)

class BinXML:
    def __init__(self, buf, offset):
        header_token, major_version, minor_version, flags, next_token = struct.unpack_from("<BBBBB", buf, offset)

        if next_token == 0x0C:
            self._element = TemplateInstance(buf, offset + 4)
        elif next_token == 0x01 or next_token == 0x41:
            self._element = Element(buf, offset + 4)
        else:
            print("Unknown binxml token", hex(next_token))

        self.length = 4 + self._element.length

    def xml(self, template=None):
        return self._element.xml(template)

class ResultSet:
    def __init__(self, buf):
        total_size, header_size, event_offset, bookmark_offset, binxml_size = struct.unpack_from("<IIIII", buf)
        self._xml = BinXML(buf, 0x14)

    def xml(self):
        return self._xml.xml()
