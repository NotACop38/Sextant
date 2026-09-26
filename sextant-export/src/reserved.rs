//! Reserved identifiers for every generated-code target.
//!
//! IR names are sanitized into syntactically valid identifiers by
//! [`crate::naming`], but a valid identifier can still be a keyword, a built-in
//! type, or a name the generated code itself relies on. Emitted verbatim, such a
//! name either breaks compilation or, worse, silently changes the parse (a
//! Kaitai struct named `f4` is read as a float). This module decides which
//! sanitized identifiers are reserved and appends a suffix to them.
//!
//! Kaitai identifiers get [`KAITAI_SUFFIX`] rather than a bare trailing
//! underscore: the Kaitai compiler converts ids to lowerCamelCase (Java,
//! JavaScript) and UpperCamelCase (class names), and both conversions drop a
//! trailing underscore, so `class_` would still become the Java field `class`
//! and a type `none_` the Python class `None`. ImHex and 010 identifiers are
//! emitted as written, so they get [`TEMPLATE_SUFFIX`]. A sanitized identifier
//! never ends in an underscore, so a template suffix can never collide with
//! another field. Kaitai names that could collide after the suffix are
//! de-duplicated by the type and field allocators or rejected by the capability
//! check.
//!
//! Every list is sorted so lookups can use a binary search; a unit test keeps
//! them sorted and unique.

use crate::ExportFormat;
use crate::naming::pascal;

/// The suffix appended to a reserved Kaitai identifier. It survives the Kaitai
/// compiler's camel-case conversions, unlike a bare trailing underscore.
pub(crate) const KAITAI_SUFFIX: &str = "_x";

/// The suffix appended to a reserved ImHex or 010 identifier.
pub(crate) const TEMPLATE_SUFFIX: &str = "_";

/// The Kaitai namespace an identifier is emitted into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KaitaiRole {
    /// A `seq` attribute id. Python and C++ use it as written, Java converts it
    /// to lowerCamelCase for fields and accessors.
    Field,
    /// A user type, enum, or the root id. Most targets turn it into an
    /// UpperCamelCase class; C++ appends `_t`.
    Type,
    /// An enum variant name. Python uses it as written; the other tested targets
    /// upper-case or prefix it.
    Variant,
}

/// Append [`KAITAI_SUFFIX`] when a sanitized Kaitai identifier is reserved in
/// its role.
#[must_use]
pub(crate) fn kaitai(id: String, role: KaitaiRole) -> String {
    if is_kaitai_reserved(&id, role) {
        id + KAITAI_SUFFIX
    } else {
        id
    }
}

/// Append [`TEMPLATE_SUFFIX`] when a sanitized snake_case member or variable
/// name is reserved in the ImHex or 010 language. Other targets are unchanged.
#[must_use]
pub(crate) fn member(target: ExportFormat, id: String) -> String {
    let reserved = match target {
        ExportFormat::ImHex => listed(IMHEX_RESERVED, &id),
        ExportFormat::Bt => listed(BT_RESERVED, &id),
        ExportFormat::Kaitai | ExportFormat::Wireshark => false,
    };
    if reserved { id + TEMPLATE_SUFFIX } else { id }
}

/// Append [`TEMPLATE_SUFFIX`] when a PascalCase type, enum, or 010 enum
/// constant name is reserved. Only 010 shares one namespace between these names
/// and its built-in types and functions; ImHex built-ins are all lowercase.
#[must_use]
pub(crate) fn type_name(target: ExportFormat, id: String) -> String {
    if target == ExportFormat::Bt && listed(BT_GLOBAL_RESERVED, &id) {
        id + TEMPLATE_SUFFIX
    } else {
        id
    }
}

fn listed(list: &[&str], id: &str) -> bool {
    list.binary_search(&id).is_ok()
}

fn is_kaitai_reserved(id: &str, role: KaitaiRole) -> bool {
    if listed(KAITAI_EXPRESSION, id) || listed(YAML_SPECIAL, id) {
        return true;
    }
    match role {
        KaitaiRole::Field => {
            listed(PYTHON_KEYWORDS, id)
                || listed(JAVA_KEYWORDS, id)
                || listed(CPP_KEYWORDS, id)
                || listed(GENERATED_MEMBERS, id)
        }
        KaitaiRole::Variant => listed(PYTHON_KEYWORDS, id) || id == "mro",
        KaitaiRole::Type => {
            is_kaitai_builtin_type(id)
                || listed(CPP_TYPE_BASES, id)
                || listed(CLASS_NAMES, &pascal(id, ""))
        }
    }
}

/// Whether `id` is (or is shaped like) a Kaitai built-in type name.
///
/// Kaitai 0.11 reads `u1`, `s1`, `u2`..`s8` and `f4`/`f8` with an optional
/// `le`/`be` suffix, `b` followed by any digits with an optional suffix, `str`,
/// and `strz` as built-in types, so a user type with one of these names is never
/// looked up. Every `[usfb]<digits>[le|be]` name is reserved, which also covers
/// widths a future compiler might add.
fn is_kaitai_builtin_type(id: &str) -> bool {
    if id == "str" || id == "strz" {
        return true;
    }
    let Some(rest) = id.strip_prefix(['u', 's', 'f', 'b']) else {
        return false;
    };
    let digits = rest
        .strip_suffix("le")
        .or_else(|| rest.strip_suffix("be"))
        .unwrap_or(rest);
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

/// Words the Kaitai expression language parses as literals or operators.
const KAITAI_EXPRESSION: &[&str] = &[
    "and",
    "as",
    "bitsizeof",
    "false",
    "not",
    "or",
    "sizeof",
    "true",
];

/// Plain scalars the Kaitai compiler's YAML 1.1 loader reads as booleans or
/// null, so an unquoted `id: yes` silently becomes the id `true`.
const YAML_SPECIAL: &[&str] = &["false", "no", "null", "off", "on", "true", "yes"];

/// Python 3 hard keywords (the capitalized `False`, `None`, and `True` are
/// covered through [`CLASS_NAMES`]).
const PYTHON_KEYWORDS: &[&str] = &[
    "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif",
    "else", "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda",
    "nonlocal", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
];

/// Java keywords and literals. Java field and accessor names are the
/// lowerCamelCase form, which equals the snake_case id for a single word.
const JAVA_KEYWORDS: &[&str] = &[
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "false",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "null",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "true",
    "try",
    "void",
    "volatile",
    "while",
];

/// C++20 keywords and alternative operator tokens. C++ accessors use the id as
/// written.
const CPP_KEYWORDS: &[&str] = &[
    "alignas",
    "alignof",
    "and",
    "and_eq",
    "asm",
    "auto",
    "bitand",
    "bitor",
    "bool",
    "break",
    "case",
    "catch",
    "char",
    "char16_t",
    "char32_t",
    "char8_t",
    "class",
    "co_await",
    "co_return",
    "co_yield",
    "compl",
    "concept",
    "const",
    "const_cast",
    "consteval",
    "constexpr",
    "constinit",
    "continue",
    "decltype",
    "default",
    "delete",
    "do",
    "double",
    "dynamic_cast",
    "else",
    "enum",
    "explicit",
    "export",
    "extern",
    "false",
    "float",
    "for",
    "friend",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "mutable",
    "namespace",
    "new",
    "noexcept",
    "not",
    "not_eq",
    "nullptr",
    "operator",
    "or",
    "or_eq",
    "private",
    "protected",
    "public",
    "register",
    "reinterpret_cast",
    "requires",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "static_assert",
    "static_cast",
    "struct",
    "switch",
    "template",
    "this",
    "thread_local",
    "throw",
    "true",
    "try",
    "typedef",
    "typeid",
    "typename",
    "union",
    "unsigned",
    "using",
    "virtual",
    "void",
    "volatile",
    "wchar_t",
    "while",
    "xor",
    "xor_eq",
];

/// Field ids whose generated member would clash with a method the target
/// already defines: `java.lang.Object` accessors in their snake_case form, the
/// Python `KaitaiStruct.close` used by `with` blocks, and the Go `Read` method.
///
/// JavaScript needs no entry: the compiler emits ids only as property names,
/// where reserved words are valid. Go keywords need none either, since Go ids
/// are exported UpperCamelCase names.
const GENERATED_MEMBERS: &[&str] = &[
    "clone",
    "close",
    "finalize",
    "get_class",
    "hash_code",
    "notify",
    "notify_all",
    "read",
    "to_string",
    "wait",
];

/// Type snake_case names whose C++ class name (`<name>_t`) is a keyword or a
/// fixed-width integer type the generated code uses unqualified.
const CPP_TYPE_BASES: &[&str] = &[
    "char16", "char32", "char8", "int16", "int32", "int64", "int8", "uint16", "uint32", "uint64",
    "uint8", "wchar",
];

/// UpperCamelCase class names that generated Python, Java, or JavaScript
/// already uses. A nested user type with one of these names shadows the
/// runtime or standard type (or is a Python keyword).
const CLASS_NAMES: &[&str] = &[
    "Array",
    "ArrayList",
    "Arrays",
    "Boolean",
    "Byte",
    "ByteBufferKaitaiStream",
    "BytesIO",
    "Character",
    "Charset",
    "Double",
    "Error",
    "Exception",
    "False",
    "Float",
    "HashMap",
    "IOException",
    "IntEnum",
    "Integer",
    "JSON",
    "KaitaiStream",
    "KaitaiStruct",
    "List",
    "Long",
    "Map",
    "Math",
    "None",
    "Number",
    "Object",
    "Short",
    "StandardCharsets",
    "String",
    "Symbol",
    "True",
    "Uint8Array",
];

/// ImHex pattern-language keywords, built-in value types, literals, and the
/// `std` namespace the generated pattern calls into.
const IMHEX_RESERVED: &[&str] = &[
    "addressof",
    "as",
    "auto",
    "be",
    "bitfield",
    "bool",
    "break",
    "catch",
    "char",
    "char16",
    "const",
    "continue",
    "double",
    "else",
    "enum",
    "false",
    "float",
    "fn",
    "for",
    "from",
    "if",
    "import",
    "in",
    "is",
    "le",
    "match",
    "namespace",
    "null",
    "out",
    "padding",
    "parent",
    "ref",
    "return",
    "s128",
    "s16",
    "s24",
    "s32",
    "s48",
    "s64",
    "s8",
    "s96",
    "signed",
    "sizeof",
    "std",
    "str",
    "struct",
    "this",
    "true",
    "try",
    "typenameof",
    "u128",
    "u16",
    "u24",
    "u32",
    "u48",
    "u64",
    "u8",
    "u96",
    "union",
    "unsigned",
    "using",
    "while",
];

/// 010 Editor keywords, C keywords, and lowercase built-in type names.
const BT_RESERVED: &[&str] = &[
    "auto",
    "bool",
    "break",
    "byte",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "dosdate",
    "dostime",
    "double",
    "else",
    "enum",
    "exists",
    "extern",
    "false",
    "filetime",
    "float",
    "for",
    "function_exists",
    "goto",
    "hfloat",
    "if",
    "inline",
    "int",
    "int16",
    "int32",
    "int64",
    "local",
    "long",
    "oletime",
    "parentof",
    "quad",
    "register",
    "return",
    "short",
    "signed",
    "sizeof",
    "startof",
    "static",
    "string",
    "struct",
    "switch",
    "this",
    "time64_t",
    "time_t",
    "true",
    "typedef",
    "ubyte",
    "uchar",
    "uint",
    "uint16",
    "uint32",
    "uint64",
    "ulong",
    "union",
    "unsigned",
    "uquad",
    "ushort",
    "void",
    "volatile",
    "wchar_t",
    "while",
    "wstring",
];

/// Global 010 names a generated PascalCase typedef, enum, or enum constant could
/// spell (single-letter words upper-case, so `d_w_o_r_d` becomes `DWORD`): the
/// upper-case built-in types and constants, and the functions the template
/// calls.
const BT_GLOBAL_RESERVED: &[&str] = &[
    "BYTE",
    "BigEndian",
    "CHAR",
    "DOSDATE",
    "DOSTIME",
    "DOUBLE",
    "DWORD",
    "FALSE",
    "FEof",
    "FILETIME",
    "FLOAT",
    "FTell",
    "FileSize",
    "GUID",
    "HFLOAT",
    "INT",
    "INT16",
    "INT32",
    "INT64",
    "LONG",
    "LittleEndian",
    "OLETIME",
    "QUAD",
    "QWORD",
    "SHORT",
    "TRUE",
    "UBYTE",
    "UCHAR",
    "UINT",
    "UINT16",
    "UINT32",
    "UINT64",
    "ULONG",
    "UQUAD",
    "USHORT",
    "WORD",
];

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[(&str, &[&str])] = &[
        ("KAITAI_EXPRESSION", KAITAI_EXPRESSION),
        ("YAML_SPECIAL", YAML_SPECIAL),
        ("PYTHON_KEYWORDS", PYTHON_KEYWORDS),
        ("JAVA_KEYWORDS", JAVA_KEYWORDS),
        ("CPP_KEYWORDS", CPP_KEYWORDS),
        ("GENERATED_MEMBERS", GENERATED_MEMBERS),
        ("CPP_TYPE_BASES", CPP_TYPE_BASES),
        ("CLASS_NAMES", CLASS_NAMES),
        ("IMHEX_RESERVED", IMHEX_RESERVED),
        ("BT_RESERVED", BT_RESERVED),
        ("BT_GLOBAL_RESERVED", BT_GLOBAL_RESERVED),
    ];

    #[test]
    fn lists_are_sorted_and_unique_for_binary_search() {
        for (name, list) in ALL {
            for pair in list.windows(2) {
                assert!(pair[0] < pair[1], "{name} is not sorted: {pair:?}");
            }
        }
    }

    #[test]
    fn a_suffixed_identifier_is_never_reserved_again() {
        for (name, list) in ALL {
            for word in *list {
                assert!(!word.ends_with('_'), "{name}: {word}");
                assert!(!word.ends_with(KAITAI_SUFFIX), "{name}: {word}");
            }
        }
        for role in [KaitaiRole::Field, KaitaiRole::Type, KaitaiRole::Variant] {
            for word in ["class", "f4", "none", "yes", "u8", "mro", "read"] {
                let once = kaitai(word.to_owned(), role);
                assert_eq!(kaitai(once.clone(), role), once, "{role:?} {word}");
            }
        }
    }

    #[test]
    fn kaitai_builtin_type_names_are_recognized() {
        for id in [
            "u1", "s1", "u2", "s8", "u4le", "s2be", "f4", "f8le", "f4be", "b1", "b12", "b64le",
            "b0", "b100", "str", "strz",
        ] {
            assert!(is_kaitai_builtin_type(id), "{id}");
            assert_eq!(kaitai(id.to_owned(), KaitaiRole::Type), format!("{id}_x"));
        }
        for id in [
            "u", "f", "ule", "bbe", "bytes", "bool", "u2_le", "string", "b1x",
        ] {
            assert!(!is_kaitai_builtin_type(id), "{id}");
        }
        // Built-in names are only reserved as types: a field may be called u4.
        assert_eq!(kaitai("u4".to_owned(), KaitaiRole::Field), "u4");
    }

    #[test]
    fn kaitai_roles_reserve_what_breaks_their_targets() {
        let field = |id: &str| kaitai(id.to_owned(), KaitaiRole::Field);
        let ty = |id: &str| kaitai(id.to_owned(), KaitaiRole::Type);
        let variant = |id: &str| kaitai(id.to_owned(), KaitaiRole::Variant);
        for id in [
            "class", "def", "true", "not", "yes", "null", "wait", "read", "delete",
        ] {
            assert_eq!(field(id), format!("{id}_x"));
        }
        for id in [
            "none",
            "true",
            "object",
            "string",
            "kaitai_struct",
            "uint8",
            "f4",
            "on",
        ] {
            assert_eq!(ty(id), format!("{id}_x"));
        }
        for id in ["class", "def", "mro", "true", "off"] {
            assert_eq!(variant(id), format!("{id}_x"));
        }
        // Common names that no tested target reserves stay as written.
        for id in [
            "type", "length", "data", "function", "map", "value", "record",
        ] {
            assert_eq!(field(id), id);
        }
        for id in ["record", "chunk", "header", "type"] {
            assert_eq!(ty(id), id);
        }
        for id in ["default", "new", "none", "name", "value"] {
            assert_eq!(variant(id), id);
        }
    }

    #[test]
    fn template_names_use_their_own_reserved_sets() {
        assert_eq!(member(ExportFormat::ImHex, "u8".into()), "u8_");
        assert_eq!(member(ExportFormat::ImHex, "std".into()), "std_");
        assert_eq!(member(ExportFormat::ImHex, "local".into()), "local");
        assert_eq!(member(ExportFormat::Bt, "local".into()), "local_");
        assert_eq!(member(ExportFormat::Bt, "u8".into()), "u8");
        // The Lua and Kaitai member namespaces are not handled here.
        assert_eq!(member(ExportFormat::Wireshark, "local".into()), "local");
        assert_eq!(type_name(ExportFormat::Bt, "FileSize".into()), "FileSize_");
        assert_eq!(type_name(ExportFormat::Bt, "DWORD".into()), "DWORD_");
        assert_eq!(
            type_name(ExportFormat::ImHex, "FileSize".into()),
            "FileSize"
        );
    }
}
