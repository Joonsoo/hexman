// 기본적으로 제공되는건 read와 as** 시리즈뿐
constructor byte = read()
constructor ubyte = read()
constructor short = read(2).asSignedInt(littleEndian)		// signed int, little-endian
constructor ushort = read(2).asSignedInt(littleEndian)		// unsigned int, little-endian
constructor int = read(4)			// signed int, little-endian
constructor uint = read(4)			// unsigned int, little-endian
constructor long = read(8)			// signed int, little-endian
constructor ulong = read(8)		// unsigned int, little-endian
constructor ubyte[length] = read(length)
constructor [T] T[length] = read(T, length)
constructor sha1 = ubyte[20]

constructor sleb128 = {read(signed LEB128, variable-length (see below)}
constructor uleb128 = {read(unsigned LEB128, variable-length (see below)}
constructor uleb128p1 = {read(unsigned LEB128 plus 1, variable-length (see below)}

// @alignment(4) 처럼 annotation 할 수 있게 추가

// constructor: type으로써의 의미, 값을 얻어내는(매핑하는) 방법

constructor encoded_value = (
	`firstByte: ubyte
	value_arg: (`firstByte >> 5).asUnsignedByte
	value_type: (`firstByte & 0x1f).asEnum(Value, {	// enum 이름은 optional
		0x00 = VALUE_BYTE
		0x02 = VALUE_SHORT
		0x03 = VALUE_CHAR
		0x04 = VALUE_INT
		0x06 = VALUE_LONG
		0x10 = VALUE_FLOAT
		0x11 = VALUE_DOUBLE
		0x15 = VALUE_METHOD_TYPE
		0x16 = VALUE_METHOD_HANDLE
		0x17 = VALUE_STRING
		0x18 = VALUE_TYPE
		0x19 = VALUE_FIELD
		0x1a = VALUE_METHOD
		0x1b = VALUE_ENUM
		0x1c = VALUE_ARRAY
		0x1d = VALUE_ANNOTATION
		0x1e = VALUE_NULL
		0x1f = VALUE_BOOLEAN
	})
	// value_type에 따라 value의 type이 달라짐
	value: value_type match {
		VALUE_BYTE =>
			value_arg == 0; ubyte
		VALUE_SHORT =>
			ubyte[value_arg + 1].signExtended.asSignedShort(littleEndian)
		VALUE_CHAR =>
			ubyte[value_arg + 1].zeroExtended.asUnsignedChar(littleEndian)
		VALUE_INT =>
			ubyte[value_arg + 1].signExtended.asSignedInt(littleEndian)
		VALUE_LONG =>
			ubyte[value_arg + 1].signExtended.asSignedLong(littleEndian)
		VALUE_FLOAT =>
			ubyte[value_arg + 1].signExtended.asFloat(littleEndian)
		VALUE_DOUBLE =>
			ubyte[value_arg + 1].signExtended.asDouble(littleEndian)
		VALUE_METHOD_TYPE | VALUE_METHOD_HANDLE | VALUE_STRING | 
		VALUE_TYPE | VALUE_FIELD | VALUE_METHOD | VALUE_ENUM =>
			ubyte[value_arg + 1].signExtended.asUnsignedInt(littleEndian)
		VALUE_ARRAY =>
			assert(value_arg == 0); encoded_array
		VALUE_ANNOTATION =>
			assert(value_arg == 0); encoded_annotation
		VALUE_NULL =>
			null
		VALUE_BOOLEAN =>
			assert(value_arg == 0 || value_arg == 1); (if (value_arg == 0) true else false):boolean
	}
)

constructor encoded_array = (
	size: uleb128
	values: encoded_value[size]
)

constructor encoded_annotation = (
	type_idx: uleb128
	size: uleb128
	elements: annotation_element[size]
)

constructor annotation_element = (
	name_idx: uleb128
	value: encoded_value
)

constructor DexFile = (
	header: header_item

	@at(header.string_ids_off)		// 현재 위치의 offset에 대한 assertion
	string_ids: string_id_item[header.string_ids_size]
	strings: string_ids map { string_id =>
		move(string_id.string_data_off); string_data_item
	}

	move(header.type_ids_off)
	type_ids: type_id_item[header.type_ids_size]
	types = type_ids map { type_id =>
		Type(strings[type_id.descriptor_idx])
	}

	move(header.proto_ids_off)
	proto_ids: proto_id_item[header.proto_ids_size]
	protos = proto_ids map { proto_id =>
		`parameters = if (proto_id.parameters_off == 0) null else {
			move(proto_id.parameters_off)
			(_: type_list).list map { typeItem =>
				types[typeItem.type_idx]
			}
		}
		Proto(strings[proto_id.shorty_idx], types[proto_id.return_type_idx], `parameters)
	}

	move(header.field_ids_off)
	field_ids: field_id_item[header.field_ids_size]
	fields = field_ids map { field_id =>
		Field(types[field_id.class_idx], types[field_id.type_idx], strings[field_id.name_idx])
	}

	move(header.method_ids_off)
	method_ids: method_id_item[header.method_ids_size]
	methods = method_ids map { method_id =>
		Method(types[method_id.class_idx], protos[method_id.proto_idx], strings[method_id.name_idx])
	}

	move(header.class_defs_off)
	class_defs: class_def_item[header.class_defs_size]

	class_datas: class_data_item

	call_site_ids: call_site_id_item[]

	move(header.method_ids_off)
	method_handles: method_handle_item[header.method_ids_size]

	move(header.data_off)
	data: ubyte[header.data_size]

	move(header.link_off)
	link_data: ubyte[header.link_size]
)

val DEX_FILE_MAGIC: ubyte[8] = { 0x64 0x65 0x78 0x0a 0x30 0x33 0x38 0x00 }

constructor header_item = (
	magic: read(8) == DEX_FILE_MAGIC
	checksum: uint
	signature: sha1
	file_size: uint
	header_size: uint
	endian_tag: uint == ENDIAN_CONSTANT

	link_size: uint
	link_off: uint

	map_off: uint

	string_ids_size: uint
	string_ids_off: uint
	type_ids_size: uint
	type_ids_off: uint
	proto_ids_size: uint
	proto_ids_off: uint
	field_ids_size: uint
	field_ids_off: uint
	method_ids_size: uint
	method_ids_off: uint
	class_defs_size: uint
	class_defs_off: uint
	data_size: uint
	data_off: uint
)

constructor string_id_item = (
	string_data_off: uint
)

constructor string_data_item = (
	utf16_size: uleb128
	data: readUntil(0)
)

constructor type_id_item = (
	descriptor_idx: uint
)

constructor proto_id_item = (
	shorty_idx: uint
	return_type_idx: uint
	parameters_off: uint
)

constructor field_id_item = (
	class_idx: ushort
	type_idx: ushort
	name_idx: uint
)

constructor method_id_item = (
	class_idx: ushort
	proto_idx: ushort
	name_idx: uint
)

constructor class_def_item = (
	class_idx: uint
	access_flags: uint
	superclass_idx: uint
	interfaces_off: uint
	source_file_idx: uint
	annotations_off: uint
	class_data_off: uint
	static_values_off: uint
)

constructor call_site_id_item = (
	call_site_off: uint
)

constructor call_site_item: encoded_array_item

constructor method_handle_item = (
	method_handle_type: ushort
	`unused1: ushort
	field_or_method_id: ushort
	`unused2: ushort
)

constructor class_data_item = (
	static_fields_size: uleb128
	instance_fields_size: uleb128
	direct_methods_size: uleb128
	virtual_methods_size: uleb128
	static_fields: encoded_field[static_fields_size]
	instance_fields: encoded_field[instance_fields_size]
	direct_methods: encoded_method[direct_methods_size]
	virtual_methods: encoded_method[virtual_methods_size]
)

constructor encoded_field = (
	field_idx_diff: uleb128
	access_flags: uleb128
)

constructor encoded_method = (
	method_idx_diff: uleb128
	access_flags: uleb128
	code_off: uleb128
)

constructor type_list = (
	size: uint
	list: type_item[size]
)

constructor type_item = (
	type_idx: ushort
)

constructor code_item = (
	registers_size: ushort
	ins_size: ushort
	outs_size: ushort
	tries_size: ushort
	debug_info_off: uint
	insns_size: uint
	insns: ushort

	if (tries_size != 0 and (insns_size % 2 == 0)) {
		// padding
		read(2) == 0
	}
	tries: try_item[tries_size]
	handlers: encoded_catch_handler_list[tries_size]
)

constructor try_item = (
	start_addr: uint
	insn_count: ushort
	handler_off: ushort
)

constructor encoded_catch_handler_list = (
	size: uleb128
	list: encoded_catch_handler[handlers_size]
)

constructor encoded_catch_handler = (
	size: sleb128
	handlers: encoded_type_addr_pair[abs(size)]
	catch_all_addr: uleb128? = if (size <= 0) uleb128 else none
)

constructor encoded_type_addr_pair = (
	type_idx: uleb128
	addr: uleb128
)

constructor debug_info_item = (
	line_start: uleb128
	parameters_size: uleb128
	parameters_name: uleb128p1[parameters_size]
)

constructor annotations_directory_item = (
	class_annotations_off: uint
	fields_size: uint
	annotated_methods_size: uint
	annotated_parameters_size: uint
	field_annotations: field_annotation[fields_size]
	method_annotations: method_annotation[annotated_methods_size]
	parameter_annotations: parameter_annotation[annotated_parameters_size]
)

constructor field_annotation = (
	field_idx: uint
	annotations_off: uint
)

constructor method_annotation = (
	method_idx: uint
	annotations_off: uint
)

constructor parameter_annotation = (
	method_idx: uint
	annotations_off: uint
)

constructor annotation_set_ref_list = (
	size: uint
	list: annotation_set_ref_item[size]
)

constructor annotation_set_ref_item = (
	annotations_off: uint
)

constructor annotation_set_item = (
	size: uint
	entries: annotation_off_item[size]
)

constructor annotation_off_item = (
	annotation_off: uint
)

constructor annotation_item = (
	visibility: ubyte.asEnum(Visibility, {
		0x00 = VISIBILITY_BUILD
		0x01 = VISIBILITY_RUNTIME
		0x02 = VISIBILITY_SYSTEM
	})
	annotation: encoded_annotation
)

constructor encoded_array_item = (
	value: encoded_array
)
