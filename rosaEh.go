package quic

// https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
// Using velues meant for experimentation
const SERVICE_ANNOUNCEMENT uint8 = 0x1e
const SERVICE_REQUEST uint8 = 0x3e
const SERVICE_RESPONSE uint8 = 0x5e
const SERVICE_AFFINITY uint8 = 0x7e

// Entries in Service Request/Response. These will be encoded as TLVs
const INSTANCE_IP uint8 = 0x1
const SERVICE_ID uint8 = 0x2
const CONSTRAINT uint8 = 0x3
const CLIENT_IP uint8 = 0x4
const INGRESS_IP uint8 = 0x5
const PORT uint8 = 0x6
const EGRESS_IP uint8 = 0x7
const INSTANCE_PORT uint8 = 0x8
const PACKETID uint8 = 0x9
const CLIENT_CONNECTIONID uint8 = 0xa
const INSTANCE_CONNECTIONID uint8 = 0xb
const ID_MODE uint8 = 0xc
const RESPONSE = 0xe
const REQUEST_SENT uint8 = 0xf

// Standardized ROSA Field (e.g. for instance IP)
type ROSAOptionTLVField struct {
	FieldType, FieldLength uint8
	FieldData              []byte
}

// Prepare one ROSA TLV Field, e.g., for Instance IP
func serializeROSAOptionTLVField(tlvField *ROSAOptionTLVField) (uint8, []byte) {
	tlvField.FieldLength = uint8(len(tlvField.FieldData))
	var buf []byte
	buf = append(buf, byte(tlvField.FieldType), byte(tlvField.FieldLength))
	buf = append(buf, tlvField.FieldData...)
	return tlvField.FieldLength + 2, buf
}

// Serialize all defined fields, e.g., for a Service Request
func SerializeAllROSAOptionFields(tlvFields *[]ROSAOptionTLVField) (uint8, []byte) {
	var buf []byte
	var totalLength uint8 = 0
	for _, tlvField := range *tlvFields {
		length, data := serializeROSAOptionTLVField(&tlvField)
		totalLength += length
		buf = append(buf, data...)
	}
	return totalLength, buf
}

// Decode one TLV field from option data and return a truncated remaining buffer
func decodeAndTruncateOneField(buf []byte) (*ROSAOptionTLVField, []byte) {
	tlvField := &ROSAOptionTLVField{}
	tlvField.FieldType = uint8(buf[0])
	tlvField.FieldLength = uint8(buf[1])
	tlvField.FieldData = buf[2 : tlvField.FieldLength+2]
	return tlvField, buf[tlvField.FieldLength+2:]
}

// Decode all TLV fields from option data associated with a ROSA Destination Option EH
func DecodeROSAOptionTLVFields(optionData []byte) []*ROSAOptionTLVField {
	optionDataCopy := optionData[4:]
	decodedTLVFields := []*ROSAOptionTLVField{}
	for len(optionDataCopy) > 0 {
		// If the first byte of (truncated) optionData slice is 0, it means its padding and we don't have anything else to decode
		if optionDataCopy[0] == 0 {
			break
		}
		var decodedField *ROSAOptionTLVField
		decodedField, optionDataCopy = decodeAndTruncateOneField(optionDataCopy)
		decodedTLVFields = append(decodedTLVFields, decodedField)
	}
	return decodedTLVFields
}
