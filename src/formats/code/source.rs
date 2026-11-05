//! Source code in ~130 languages: language (extension, shebang, modeline or
//! file name), lines of code / comments / blanks, imports, top-level
//! symbols, package, module documentation, licence (SPDX tag or licence
//! header), copyright, TODO counts, and whether the file is a test,
//! generated or minified.
//!
//! Everything is line- and regex-based: no parser recursion, so hostile
//! input cannot exhaust the stack. One table row per language drives it.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, LazyLock, Mutex};

use regex::Regex;
use serde_json::{Map, json};

use crate::plugin::{
    Context, Cost, ExtractError, Extractor, ExtractorMeta, FormatSpec, Probe, Sniff, Source, TextRole, find_copyright,
    identify_license, spdx_identifier, truncate_chars,
};

/// Extractor for source code.
pub struct SourceCode;

/// Syntax of one language.
struct Lang {
    id: &'static str,
    /// Line-comment markers. Markers starting with a letter (`REM`) only count at the start of a line.
    line: &'static [&'static str],
    /// Block-comment delimiters.
    block: &'static [(&'static str, &'static str)],
    /// String delimiters.
    quotes: &'static [u8],
    /// Regexes whose first group is an imported module.
    imports: &'static [&'static str],
    /// `(kind, regex)`: the last group is the symbol name.
    symbols: &'static [(&'static str, &'static str)],
    /// Regex whose first group is the package / namespace.
    package: &'static str,
}

macro_rules! languages {
    ($( $id:literal $name:literal $mime:literal [$($ext:literal),*] {
        line: [$($lc:literal),*], block: [$(($bo:literal, $bc:literal)),*], quotes: $q:literal,
        imports: [$($imp:literal),*], symbols: [$(($sk:literal, $sr:literal)),*], package: $pkg:literal
    } )*) => {
        static FORMATS: &[FormatSpec] = &[$(FormatSpec {
            id: $id, name: $name, family: "code.source", mimes: &[$mime], extensions: &[$($ext),*],
            magic: &[], parent: Some("text"),
        }),*];
        static LANGS: &[Lang] = &[$(Lang {
            id: $id, line: &[$($lc),*], block: &[$(($bo, $bc)),*], quotes: $q,
            imports: &[$($imp),*], symbols: &[$(($sk, $sr)),*], package: $pkg,
        }),*];
    };
}

// Patterns are applied with multi-line mode on; `^` is the start of a line,
// so most symbol patterns only match top-level (unindented) definitions.
languages! {
    "c" "C source" "text/x-c" ["c", "h"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"^\s*#\s*include\s*[<"]([^>"]+)[>"]"#],
        symbols: [("function", r"^[A-Za-z_][\w \t\*]*?(?-u:\b)([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{?\s*$"), ("struct", r"^(?:typedef\s+)?struct\s+(\w+)"), ("enum", r"^(?:typedef\s+)?enum\s+(\w+)"), ("macro", r"^#\s*define\s+(\w+)")],
        package: ""
    }
    "cpp" "C++ source" "text/x-c++" ["cpp", "cc", "cxx", "c++", "hpp", "hh", "hxx", "h++", "ipp", "inl", "tpp"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"^\s*#\s*include\s*[<"]([^>"]+)[>"]"#, r"^\s*import\s+([\w.:<>]+)\s*;"],
        symbols: [("function", r"^[A-Za-z_][\w \t\*&:<>,]*?(?-u:\b)([A-Za-z_][\w:~]*)\s*\([^;{]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{?\s*$"), ("class", r"^(?:template\s*<[^>]*>\s*)?(?:class|struct)\s+(\w+)"), ("namespace", r"^namespace\s+([\w:]+)"), ("macro", r"^#\s*define\s+(\w+)")],
        package: r"^namespace\s+([\w:]+)"
    }
    "cuda" "CUDA source" "text/x-cuda" ["cu", "cuh"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"^\s*#\s*include\s*[<"]([^>"]+)[>"]"#],
        symbols: [("kernel", r"__global__\s+\w[\w\s\*]*?(?-u:\b)(\w+)\s*\("), ("function", r"^(?:__device__\s+|__host__\s+)*[A-Za-z_][\w \t\*]*?(?-u:\b)([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{?\s*$")],
        package: ""
    }
    "csharp" "C# source" "text/x-csharp" ["cs", "csx"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r"^\s*(?:global\s+)?using\s+(?:static\s+)?([\w.]+)\s*;"],
        symbols: [("type", r"^\s{0,8}(?:(?:public|private|protected|internal|abstract|sealed|static|partial|readonly|file)\s+)*(?:class|interface|struct|enum|record)\s+(\w+)")],
        package: r"^\s*namespace\s+([\w.]+)"
    }
    "java" "Java source" "text/x-java" ["java"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r"^\s*import\s+(?:static\s+)?([\w.*]+)\s*;"],
        symbols: [("type", r"^\s{0,4}(?:(?:public|private|protected|abstract|final|static|sealed|non-sealed|strictfp)\s+)*(?:class|interface|enum|record|@interface)\s+(\w+)")],
        package: r"^\s*package\s+([\w.]+)\s*;"
    }
    "kotlin" "Kotlin source" "text/x-kotlin" ["kt", "kts"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r"^\s*import\s+([\w.*]+)"],
        symbols: [("type", r"^(?:(?:public|private|internal|protected|abstract|open|sealed|data|enum|annotation|inline|value)\s+)*(?:class|interface|object)\s+(\w+)"), ("function", r"^(?:(?:public|private|internal|protected|inline|suspend|override|operator|infix|tailrec)\s+)*fun\s+(?:<[^>]*>\s*)?(?:[\w.<>]+\.)?(\w+)")],
        package: r"^\s*package\s+([\w.]+)"
    }
    "scala" "Scala source" "text/x-scala" ["scala", "sc"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r"^\s*import\s+([\w.{}, _*]+)"],
        symbols: [("type", r"^(?:(?:abstract|final|sealed|case|implicit|private|protected)\s+)*(?:class|trait|object|enum)\s+(\w+)"), ("function", r"^\s{0,2}def\s+(\w+)")],
        package: r"^\s*package\s+([\w.]+)"
    }
    "groovy" "Groovy / Gradle script" "text/x-groovy" ["groovy", "gradle", "gvy"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r"^\s*import\s+(?:static\s+)?([\w.*]+)", r#"^\s*(?:id|apply\s+plugin:)\s*\(?\s*['"]([\w.-]+)['"]"#],
        symbols: [("type", r"^(?:(?:public|abstract|final)\s+)*(?:class|interface|enum|trait)\s+(\w+)"), ("function", r"^def\s+(\w+)\s*\(")],
        package: r"^\s*package\s+([\w.]+)"
    }
    "go" "Go source" "text/x-go" ["go"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'`",
        imports: [r#"^\s*import\s+(?:[\w.]+\s+)?"([^"]+)""#],
        symbols: [("function", r"^func\s+(?:\([^)]*\)\s*)?(\w+)"), ("type", r"^type\s+(\w+)")],
        package: r"^package\s+(\w+)"
    }
    "rust" "Rust source" "text/rust" ["rs"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r"^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+(?:::)?(\w+)", r"^\s*extern\s+crate\s+(\w+)"],
        symbols: [("function", r"^(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\S+\s+)?fn\s+(\w+)"), ("struct", r"^(?:pub(?:\([^)]*\))?\s+)?struct\s+(\w+)"), ("enum", r"^(?:pub(?:\([^)]*\))?\s+)?enum\s+(\w+)"), ("trait", r"^(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?trait\s+(\w+)"), ("impl", r"^impl(?:<[^>]*>)?\s+(?:[\w:<>, ]+\s+for\s+)?([\w:]+)"), ("module", r"^(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)"), ("macro", r"^macro_rules!\s+(\w+)")],
        package: ""
    }
    "swift" "Swift source" "text/x-swift" ["swift"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r"^\s*(?:@testable\s+)?import\s+(?:class\s+|struct\s+|func\s+)?(\w+)"],
        symbols: [("type", r"^(?:(?:public|private|internal|fileprivate|open|final)\s+)*(?:class|struct|enum|protocol|extension|actor)\s+(\w+)"), ("function", r"^(?:(?:public|private|internal|fileprivate|open|static)\s+)*func\s+(\w+)")],
        package: ""
    }
    "dart" "Dart source" "application/dart" ["dart"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"^\s*(?:import|export)\s+['"]([^'"]+)['"]"#],
        symbols: [("type", r"^(?:abstract\s+|sealed\s+|base\s+|final\s+)*(?:class|mixin|enum|extension)\s+(\w+)")],
        package: r"^\s*library\s+([\w.]+)"
    }
    "javascript" "JavaScript source" "text/javascript" ["js", "mjs", "cjs", "jsx"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'`",
        imports: [r#"^\s*import\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]"#, r#"(?-u:\b)require\(\s*['"]([^'"]+)['"]\s*\)"#, r#"^\s*export\s+[^'";]*?\s+from\s+['"]([^'"]+)['"]"#],
        symbols: [("function", r"^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(\w+)"), ("class", r"^(?:export\s+)?(?:default\s+)?class\s+(\w+)"), ("function", r"^(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>")],
        package: ""
    }
    "typescript" "TypeScript source" "application/typescript" ["ts", "mts", "cts", "tsx"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'`",
        imports: [r#"^\s*import\s+(?:type\s+)?(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]"#, r#"(?-u:\b)require\(\s*['"]([^'"]+)['"]\s*\)"#, r#"^\s*export\s+[^'";]*?\s+from\s+['"]([^'"]+)['"]"#],
        symbols: [("function", r"^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(\w+)"), ("class", r"^(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+(\w+)"), ("interface", r"^(?:export\s+)?(?:declare\s+)?interface\s+(\w+)"), ("type", r"^(?:export\s+)?(?:declare\s+)?type\s+(\w+)"), ("enum", r"^(?:export\s+)?(?:declare\s+)?(?:const\s+)?enum\s+(\w+)"), ("function", r"^(?:export\s+)?(?:const|let)\s+(\w+)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*(?::[^=]+)?=>")],
        package: r"^\s*(?:declare\s+)?(?:module|namespace)\s+([\w.]+)"
    }
    "vue" "Vue single-file component" "text/x-vue" ["vue"] {
        line: ["//"], block: [("<!--", "-->"), ("/*", "*/")], quotes: b"\"'`",
        imports: [r#"^\s*import\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]"#],
        symbols: [("section", r"^<(template|script|style)(?-u:\b)")],
        package: ""
    }
    "svelte" "Svelte component" "text/x-svelte" ["svelte"] {
        line: ["//"], block: [("<!--", "-->"), ("/*", "*/")], quotes: b"\"'`",
        imports: [r#"^\s*import\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]"#],
        symbols: [("section", r"^<(script|style)(?-u:\b)")],
        package: ""
    }
    "css" "CSS stylesheet" "text/css" ["css"] {
        line: [], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"@import\s+(?:url\()?\s*['"]?([^'")\s;]+)"#],
        symbols: [("custom_property", r"^\s*(--[\w-]+)\s*:"), ("keyframes", r"@keyframes\s+([\w-]+)"), ("font_face", r"(@font-face)")],
        package: ""
    }
    "scss" "Sass / Less stylesheet" "text/x-scss" ["scss", "sass", "less", "styl"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"@(?:import|use|forward)\s+(?:url\()?\s*['"]?([^'")\s;]+)"#],
        symbols: [("mixin", r"@mixin\s+([\w-]+)"), ("function", r"@function\s+([\w-]+)"), ("variable", r"^\$([\w-]+)\s*:")],
        package: ""
    }
    "python" "Python source" "text/x-python" ["py", "pyw", "pyi", "ipy"] {
        line: ["#"], block: [("\"\"\"", "\"\"\""), ("'''", "'''")], quotes: b"\"'",
        imports: [r"^\s*import\s+([\w.]+)", r"^\s*from\s+([\w.]+)\s+import(?-u:\b)"],
        symbols: [("function", r"^(?:async\s+)?def\s+(\w+)"), ("class", r"^class\s+(\w+)")],
        package: ""
    }
    "ruby" "Ruby source" "text/x-ruby" ["rb", "rbw", "rake", "gemspec", "ru"] {
        line: ["#"], block: [("=begin", "=end")], quotes: b"\"'",
        imports: [r#"^\s*require(?:_relative)?\s*\(?\s*['"]([^'"]+)['"]"#],
        symbols: [("class", r"^\s{0,2}class\s+([\w:]+)"), ("module", r"^\s{0,2}module\s+([\w:]+)"), ("method", r"^\s{0,4}def\s+(?:self\.)?([\w?!=]+)")],
        package: ""
    }
    "php" "PHP source" "application/x-httpd-php" ["php", "phtml", "php3", "php4", "php5", "phps"] {
        line: ["//", "#"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r"^\s*use\s+([\w\\]+)", r#"(?-u:\b)(?:require|include)(?:_once)?\s*\(?\s*['"]([^'"]+)['"]"#],
        symbols: [("type", r"^\s{0,4}(?:(?:abstract|final|readonly)\s+)*(?:class|interface|trait|enum)\s+(\w+)"), ("function", r"^\s{0,4}(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+&?(\w+)")],
        package: r"^\s*namespace\s+([\w\\]+)"
    }
    "perl" "Perl source" "text/x-perl" ["pl", "pm"] {
        line: ["#"], block: [("=pod", "=cut"), ("=head1", "=cut")], quotes: b"\"'",
        imports: [r"^\s*(?:use|require)\s+([\w:]+)"],
        symbols: [("function", r"^sub\s+(\w+)")],
        package: r"^\s*package\s+([\w:]+)"
    }
    "shell" "Shell script" "application/x-sh" ["sh", "bash", "zsh", "ksh", "fish", "bashrc", "zshrc", "bash_profile", "kshrc"] {
        line: ["#"], block: [], quotes: b"\"'",
        imports: [r"^\s*(?:source|\.)\s+([^\s;|&]+)"],
        symbols: [("function", r"^\s*(?:function\s+)?([\w-]+)\s*\(\)\s*\{?"), ("function", r"^\s*function\s+([\w-]+)")],
        package: ""
    }
    "powershell" "PowerShell script" "text/x-powershell" ["ps1", "psm1", "psd1"] {
        line: ["#"], block: [("<#", "#>")], quotes: b"\"'",
        imports: [r"(?i)^\s*Import-Module\s+([\w.\\/-]+)", r"(?i)^\s*using\s+module\s+([\w.\\/-]+)"],
        symbols: [("function", r"(?i)^\s*(?:function|filter)\s+([\w-]+)"), ("class", r"(?i)^\s*class\s+(\w+)")],
        package: ""
    }
    "batch" "Windows batch file" "application/x-bat" ["bat", "cmd"] {
        line: ["REM", "rem", "Rem", "@REM", "@rem", "::"], block: [], quotes: b"\"",
        imports: [r"(?i)^\s*call\s+([\w.\\/:-]+\.(?:bat|cmd))"],
        symbols: [("label", r"^:(\w+)")],
        package: ""
    }
    "lua" "Lua source" "text/x-lua" ["lua"] {
        line: ["--"], block: [("--[[", "]]")], quotes: b"\"'",
        imports: [r#"(?-u:\b)require\s*\(?\s*['"]([^'"]+)['"]"#],
        symbols: [("function", r"^\s*(?:local\s+)?function\s+([\w.:]+)")],
        package: ""
    }
    "r" "R script" "text/x-r" ["r"] {
        line: ["#"], block: [], quotes: b"\"'",
        imports: [r#"(?-u:\b)(?:library|require|requireNamespace)\(\s*['"]?([\w.]+)"#],
        symbols: [("function", r"^([\w.]+)\s*(?:<-|=)\s*function(?-u:\b)")],
        package: ""
    }
    "julia" "Julia source" "text/x-julia" ["jl"] {
        line: ["#"], block: [("#=", "=#")], quotes: b"\"",
        imports: [r"^\s*(?:using|import)\s+([\w.]+)"],
        symbols: [("function", r"^function\s+([\w.!]+)"), ("struct", r"^(?:mutable\s+)?struct\s+(\w+)"), ("module", r"^module\s+(\w+)")],
        package: ""
    }
    "haskell" "Haskell source" "text/x-haskell" ["hs"] {
        line: ["--"], block: [("{-", "-}")], quotes: b"\"",
        imports: [r"^import\s+(?:qualified\s+)?([\w.]+)"],
        symbols: [("function", r"^([a-z_][\w']*)\s*::"), ("type", r"^(?:data|newtype|type|class)\s+(\w+)")],
        package: r"^module\s+([\w.]+)"
    }
    "elixir" "Elixir source" "text/x-elixir" ["ex", "exs"] {
        line: ["#"], block: [], quotes: b"\"'",
        imports: [r"^\s*(?:alias|import|require|use)\s+([\w.]+)"],
        symbols: [("module", r"^\s*defmodule\s+([\w.]+)"), ("function", r"^\s*defp?\s+([\w?!]+)")],
        package: ""
    }
    "erlang" "Erlang source" "text/x-erlang" ["erl", "hrl"] {
        line: ["%"], block: [], quotes: b"\"",
        imports: [r#"^-include(?:_lib)?\("([^"]+)"\)"#, r"^-import\((\w+)"],
        symbols: [("function", r"^([a-z]\w*)\(.*\)\s*(?:when\s+.*)?->")],
        package: r"^-module\((\w+)\)"
    }
    "clojure" "Clojure source" "text/x-clojure" ["clj", "cljs", "cljc"] {
        line: [";"], block: [], quotes: b"\"",
        imports: [r"\[([\w.-]+)\s+:as(?-u:\b)", r"\(:require\s+\[?([\w.-]+)"],
        symbols: [("function", r"^\(defn-?\s+([^\s()\[\]]+)"), ("var", r"^\(def\s+([^\s()\[\]]+)")],
        package: r"^\(ns\s+([\w.-]+)"
    }
    "ocaml" "OCaml source" "text/x-ocaml" ["ml", "mli"] {
        line: [], block: [("(*", "*)")], quotes: b"\"",
        imports: [r"^\s*open\s+([\w.]+)"],
        symbols: [("value", r"^let\s+(?:rec\s+)?(\w+)"), ("type", r"^type\s+(?:'?\w+\s+)?(\w+)"), ("module", r"^module\s+(\w+)")],
        package: ""
    }
    "fsharp" "F# source" "text/x-fsharp" ["fs", "fsi", "fsx"] {
        line: ["//"], block: [("(*", "*)")], quotes: b"\"",
        imports: [r"^\s*open\s+([\w.]+)"],
        symbols: [("value", r"^let\s+(?:rec\s+|inline\s+|private\s+)*(\w+)"), ("type", r"^type\s+(\w+)")],
        package: r"^(?:module|namespace)\s+([\w.]+)"
    }
    "zig" "Zig source" "text/x-zig" ["zig"] {
        line: ["//"], block: [], quotes: b"\"'",
        imports: [r#"@import\("([^"]+)"\)"#],
        symbols: [("function", r"^(?:pub\s+)?(?:export\s+)?(?:inline\s+)?fn\s+(\w+)"), ("type", r"^(?:pub\s+)?const\s+(\w+)\s*=\s*(?:packed\s+|extern\s+)?(?:struct|enum|union|opaque)")],
        package: ""
    }
    "objective_c" "Objective-C++ source" "text/x-objective-c++" ["mm"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"^\s*#\s*(?:import|include)\s*[<"]([^>"]+)[>"]"#, r"^\s*@import\s+([\w.]+)"],
        symbols: [("class", r"^@(?:interface|implementation|protocol)\s+(\w+)")],
        package: ""
    }
    "matlab" "MATLAB / Octave script" "text/x-matlab" ["m"] {
        line: ["%", "#"], block: [("%{", "%}")], quotes: b"\"",
        imports: [r"^\s*import\s+([\w.*]+)", r"^\s*(?:addpath|pkg\s+load)\s*\(?\s*'?([\w./-]+)"],
        symbols: [("function", r"^\s*function\s+(?:\[[^\]]*\]\s*=\s*|\w+\s*=\s*)?(\w+)"), ("class", r"^classdef\s+(?:\([^)]*\)\s*)?(\w+)")],
        package: ""
    }
    "assembly" "Assembly source" "text/x-asm" ["asm", "s", "nasm"] {
        line: [";", "#"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r#"^\s*(?:%include|\.include|include)\s+['"<]?([^'">\s]+)"#],
        symbols: [("label", r"^([A-Za-z_.$][\w.$]*):"), ("section", r"^\s*(?:section|\.section)\s+([\w.]+)")],
        package: ""
    }
    "graphql" "GraphQL schema / query" "application/graphql" ["graphql", "gql", "graphqls"] {
        line: ["#"], block: [], quotes: b"\"",
        imports: [r"^#import\s+['\x22]([^'\x22]+)"],
        symbols: [("type", r"^(?:extend\s+)?(?:type|interface|enum|input|union|scalar)\s+(\w+)"), ("operation", r"^(?:query|mutation|subscription|fragment)\s+(\w+)")],
        package: ""
    }
    "latex" "LaTeX source" "application/x-tex" ["tex", "ltx", "sty", "dtx"] {
        line: ["%"], block: [], quotes: b"",
        imports: [r"\\(?:usepackage|RequirePackage)(?:\[[^\]]*\])?\{([^}]+)\}", r"\\(?:input|include)\{([^}]+)\}"],
        symbols: [("command", r"\\(?:newcommand|renewcommand|DeclareMathOperator)\*?\{?\\(\w+)"), ("environment", r"\\newenvironment\{(\w+)\}")],
        package: ""
    }
    "cmake" "CMake script" "text/x-cmake" ["cmake"] {
        line: ["#"], block: [("#[[", "]]")], quotes: b"\"",
        imports: [r"(?i)(?-u:\b)find_package\(\s*(\w+)", r"(?i)(?-u:\b)include\(\s*([\w./${}-]+)"],
        symbols: [("target", r"(?i)(?-u:\b)add_(?:executable|library)\(\s*([\w.-]+)"), ("function", r"(?i)^\s*(?:function|macro)\(\s*(\w+)")],
        package: r"(?i)(?-u:\b)project\(\s*([\w.-]+)"
    }
    "nix" "Nix expression" "text/x-nix" ["nix"] {
        line: ["#"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r"(?-u:\b)import\s+([./\w<>-]+)"],
        symbols: [("attribute", r"^\s{2}([\w-]+)\s*=")],
        package: ""
    }
    "visual_basic" "Visual Basic source" "text/x-vb" ["vb", "bas", "vbs", "vbe"] {
        line: ["'", "REM", "Rem", "rem"], block: [], quotes: b"\"",
        imports: [r"(?i)^\s*Imports\s+([\w.]+)"],
        symbols: [("procedure", r"(?i)^\s*(?:(?:Public|Private|Friend|Shared|Protected|Overrides|Async)\s+)*(?:Sub|Function)\s+(\w+)"), ("type", r"(?i)^\s*(?:(?:Public|Private|Friend|Partial|MustInherit|NotInheritable)\s+)*(?:Class|Module|Structure|Interface|Enum)\s+(\w+)")],
        package: r"(?i)^\s*Namespace\s+([\w.]+)"
    }
    "protobuf" "Protocol Buffers schema" "text/x-protobuf" ["proto"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"^\s*import\s+(?:public\s+|weak\s+)?"([^"]+)""#],
        symbols: [("message", r"^\s*message\s+(\w+)"), ("enum", r"^\s*enum\s+(\w+)"), ("service", r"^\s*service\s+(\w+)"), ("rpc", r"^\s*rpc\s+(\w+)")],
        package: r"^\s*package\s+([\w.]+)\s*;"
    }
    "thrift" "Apache Thrift schema" "application/x-thrift" ["thrift"] {
        line: ["//", "#"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"^\s*include\s+"([^"]+)""#],
        symbols: [("struct", r"^\s*struct\s+(\w+)"), ("union", r"^\s*union\s+(\w+)"), ("exception", r"^\s*exception\s+(\w+)"), ("enum", r"^\s*enum\s+(\w+)"), ("service", r"^\s*service\s+(\w+)")],
        package: r"^\s*namespace\s+\S+\s+([\w.]+)"
    }
    "capnp" "Cap'n Proto schema" "text/x-capnp" ["capnp"] {
        line: ["#"], block: [], quotes: b"\"",
        imports: [r#"import\s+"([^"]+)""#],
        symbols: [("struct", r"^\s*struct\s+(\w+)"), ("enum", r"^\s*enum\s+(\w+)"), ("interface", r"^\s*interface\s+(\w+)"), ("const", r"^\s*const\s+(\w+)")],
        package: r#"\$\w+\.namespace\("([^"]+)"\)"#
    }
    "flatbuffers" "FlatBuffers schema" "text/x-flatbuffers" ["fbs"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r#"^\s*include\s+"([^"]+)""#],
        symbols: [("table", r"^\s*table\s+(\w+)"), ("struct", r"^\s*struct\s+(\w+)"), ("enum", r"^\s*enum\s+(\w+)"), ("union", r"^\s*union\s+(\w+)"), ("service", r"^\s*rpc_service\s+(\w+)"), ("root_type", r"^\s*root_type\s+([\w.]+)")],
        package: r"^\s*namespace\s+([\w.]+)\s*;"
    }
    "dhall" "Dhall source" "text/x-dhall" ["dhall"] {
        line: ["--"], block: [("{-", "-}")], quotes: b"\"",
        imports: [r"(?:^|[\s(=])((?:https?://|\.{1,2}/|~/)[^\s)]+)"],
        symbols: [("binding", r"^let\s+([\w-]+)")],
        package: ""
    }
    "jsonnet" "Jsonnet source" "text/x-jsonnet" ["jsonnet", "libsonnet"] {
        line: ["//", "#"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"import(?:str|bin)?\s+['"]([^'"]+)['"]"#],
        symbols: [("local", r"^local\s+(\w+)")],
        package: ""
    }
    "cuelang" "CUE source" "text/x-cue" ["cue"] {
        line: ["//"], block: [], quotes: b"\"",
        imports: [r#"^\s*import\s+(?:\w+\s+)?"([^"]+)""#, r#"^\s+(?:\w+\s+)?"([\w.]+/[^"]+)"\s*$"#],
        symbols: [("definition", r"^(#\w+)\s*:"), ("field", r"^(\w+)\s*:")],
        package: r"^package\s+(\w+)"
    }
    // Stage 8: the long tail.
    "astro" "Astro component" "text/x-astro" ["astro"] {
        line: ["//"], block: [("<!--", "-->"), ("/*", "*/")], quotes: b"\"'`",
        imports: [r#"^\s*import\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]"#],
        symbols: [("section", r"^<(script|style)(?-u:\b)"), ("component", r"^\s*<([A-Z]\w*)")],
        package: ""
    }
    "nim" "Nim source" "text/x-nim" ["nim", "nims", "nimble"] {
        line: ["#"], block: [("#[", "]#")], quotes: b"\"'",
        imports: [r"^\s*(?:import|include)\s+(\w+(?:/\w+)*)", r"^\s*from\s+([\w/.]+)\s+import(?-u:\b)"],
        symbols: [("procedure", r"^(?:proc|func|method|iterator|converter)\s+`?(\w+)"), ("template", r"^(?:template|macro)\s+(\w+)"), ("type", r"^\s{0,2}(\w+)\*?(?:\[[^\]]*\])?\s*=\s*(?:ref\s+|ptr\s+)?(?:object|enum|tuple|distinct|concept)(?-u:\b)")],
        package: ""
    }
    "crystal" "Crystal source" "text/x-crystal" ["cr"] {
        line: ["#"], block: [], quotes: b"\"'",
        imports: [r#"^\s*require\s+"([^"]+)""#],
        symbols: [("class", r"^\s{0,2}(?:abstract\s+)?(?:class|struct)\s+([\w:]+)"), ("module", r"^\s{0,2}module\s+([\w:]+)"), ("method", r"^\s{0,4}(?:private\s+|protected\s+)?def\s+(?:self\.)?([\w?!=]+)"), ("macro", r"^\s{0,2}macro\s+(\w+)")],
        package: ""
    }
    "d" "D source" "text/x-d" ["d", "di"] {
        line: ["//"], block: [("/*", "*/"), ("/+", "+/")], quotes: b"\"'`",
        imports: [r"^\s*(?:public\s+|static\s+|private\s+)?import\s+(?:\w+\s*=\s*)?([\w.]+)"],
        symbols: [("type", r"^(?:(?:public|private|final|abstract)\s+)*(?:class|struct|interface|union|enum|template|mixin\s+template)\s+(\w+)"), ("function", r"^(?:(?:public|private|static|pure|nothrow|@safe|@trusted|@system|@nogc|auto|const|immutable|ref)\s+)*[\w!.\[\]*]+\s+(\w+)\s*\([^;]*\)\s*(?:\w+\s*)*\{?\s*$")],
        package: r"^module\s+([\w.]+)\s*;"
    }
    "vlang" "V source" "text/x-vlang" ["vsh"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'`",
        imports: [r"^import\s+([\w.]+)"],
        symbols: [("function", r"^(?:pub\s+)?fn\s+(?:\([^)]*\)\s*)?([\w.]+)"), ("struct", r"^(?:pub\s+)?struct\s+(\w+)"), ("enum", r"^(?:pub\s+)?enum\s+(\w+)"), ("interface", r"^(?:pub\s+)?interface\s+(\w+)")],
        package: r"^module\s+(\w+)"
    }
    "odin" "Odin source" "text/x-odin" ["odin"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'`",
        imports: [r#"^import\s+(?:\w+\s+)?"([^"]+)""#],
        symbols: [("procedure", r"^(\w+)\s*::\s*proc(?-u:\b)"), ("type", r"^(\w+)\s*::\s*(?:struct|enum|union|distinct|bit_set)(?-u:\b)")],
        package: r"^package\s+(\w+)"
    }
    "fortran" "Fortran source" "text/x-fortran" ["f", "f77", "f90", "f95", "f03", "f08", "for", "ftn", "fpp"] {
        line: ["!"], block: [], quotes: b"\"'",
        imports: [r"(?i)^\s*use\s*(?:,\s*\w+\s*::)?\s*(\w+)", r"(?i)^\s*include\s+['\x22]([^'\x22]+)"],
        symbols: [("program", r"(?i)^\s*program\s+(\w+)"), ("module", r"(?i)^\s*module\s+(\w+)\s*$"), ("procedure", r"(?i)^\s*(?:(?:pure|elemental|recursive|impure|module|integer|real|logical|complex|character|double\s+precision|type\s*\([^)]*\))(?:\s*\([^)]*\))?\s+)*(?:subroutine|function)\s+(\w+)")],
        package: ""
    }
    "cobol" "COBOL source" "text/x-cobol" ["cob", "cbl", "cpy"] {
        line: ["*>"], block: [], quotes: b"\"'",
        imports: [r"(?i)(?-u:\b)COPY\s+([\w-]+)"],
        symbols: [("division", r"(?i)^[ \d]*(IDENTIFICATION|ENVIRONMENT|DATA|PROCEDURE)\s+DIVISION"), ("section", r"(?i)^[ \d]{0,11}([\w-]+)\s+SECTION\s*\."), ("paragraph", r"(?i)^[ \d]{7}([A-Z0-9][\w-]*)\.\s*$")],
        package: r"(?i)PROGRAM-ID\.\s*([\w-]+)"
    }
    "pascal" "Pascal / Delphi source" "text/x-pascal" ["pas", "pp", "dpr", "lpr", "dpk"] {
        line: ["//"], block: [("{", "}"), ("(*", "*)")], quotes: b"'",
        imports: [r"(?i)^\s*uses\s+([\w.,\s]+?)\s*;"],
        symbols: [("routine", r"(?i)^\s*(?:class\s+)?(?:procedure|function|constructor|destructor)\s+([\w.]+)"), ("type", r"(?i)^\s*(\w+)\s*=\s*(?:packed\s+)?(?:class|record|object|interface)(?-u:\b)")],
        package: r"(?i)^\s*(?:unit|program|library|package)\s+([\w.]+)\s*;"
    }
    "ada" "Ada source" "text/x-ada" ["adb", "ads", "ada"] {
        line: ["--"], block: [], quotes: b"\"",
        imports: [r"(?i)^\s*(?:limited\s+|private\s+)*with\s+([\w.,\s]+?)\s*;"],
        symbols: [("subprogram", r"(?i)^\s*(?:overriding\s+)?(?:procedure|function)\s+([\w.]+)"), ("type", r"(?i)^\s*(?:sub)?type\s+(\w+)"), ("task", r"(?i)^\s*(?:task|protected)\s+(?:type\s+|body\s+)?(\w+)")],
        package: r"(?i)^\s*(?:private\s+)?package\s+(?:body\s+)?([\w.]+)"
    }
    "lisp" "Common Lisp / Emacs Lisp source" "text/x-common-lisp" ["lisp", "lsp", "el", "cl", "asd"] {
        line: [";"], block: [("#|", "|#")], quotes: b"\"",
        imports: [r"\(require\s+'([\w/-]+)", r##"\(ql:quickload\s+[:'"#]*([\w/-]+)"##, r"\(:use\s+(?:#?:)?([\w.-]+)", r"\(:import-from\s+#?:?([\w.-]+)"],
        symbols: [("function", r"^\((?:cl-)?def(?:un|subst|generic|method)\*?\s+\(?([^\s()]+)"), ("macro", r"^\(defmacro\s+([^\s()]+)"), ("variable", r"^\(def(?:var|parameter|const|custom|constant)\s+([^\s()]+)"), ("type", r"^\((?:defclass|defstruct|deftype|define-condition)\s+\(?([^\s()]+)")],
        package: r"^\((?:defpackage|define-package|in-package|provide)\s+['#:]*([\w./-]+)"
    }
    "scheme" "Scheme / Racket source" "text/x-scheme" ["scm", "ss", "rkt", "sls", "sps", "rktl"] {
        line: [";"], block: [("#|", "|#")], quotes: b"\"",
        imports: [r"\(require\s+([\w/.-]+)", r"^\s*\(import\s+\(([\w\s.-]+)\)"],
        symbols: [("definition", r"^\(define(?:\*|-values|-public)?\s+\(?([^\s()]+)"), ("syntax", r"^\(define-syntax(?:-rule)?\s+\(?([^\s()]+)"), ("record", r"^\(define-record-type\s+<?([^\s()>]+)"), ("struct", r"^\(struct\s+([^\s()]+)"), ("lang", r"^#lang\s+(\S+)")],
        package: r"^\((?:define-library|library|module)\s+\(?([^()\n]+)"
    }
    "prolog" "Prolog source" "text/x-prolog" ["pro", "prolog"] {
        line: ["%"], block: [("/*", "*/")], quotes: b"\"'`",
        imports: [r"^:-\s*use_module\(\s*(?:library\()?([\w/]+)", r"^:-\s*(?:consult|include|ensure_loaded)\(\s*'?([\w/.]+)"],
        symbols: [("predicate", r"^([a-z]\w*)\s*(?:\([^)]*\))?\s*(?::-|-->)"), ("fact", r"^([a-z]\w*)\([^)]*\)\s*\.\s*$")],
        package: r"^:-\s*module\(\s*(\w+)"
    }
    "elm" "Elm source" "text/x-elm" ["elm"] {
        line: ["--"], block: [("{-", "-}")], quotes: b"\"'",
        imports: [r"^import\s+([\w.]+)"],
        symbols: [("function", r"^([a-z]\w*)\s*:[^:]"), ("type", r"^type\s+(?:alias\s+)?(\w+)"), ("port", r"^port\s+(\w+)\s*:")],
        package: r"^(?:port\s+|effect\s+)?module\s+([\w.]+)"
    }
    "purescript" "PureScript source" "text/x-purescript" ["purs"] {
        line: ["--"], block: [("{-", "-}")], quotes: b"\"",
        imports: [r"^import\s+([\w.]+)"],
        symbols: [("function", r"^([a-z]\w*)\s*::"), ("type", r"^(?:data|newtype|type|class|foreign\s+import\s+data)\s+(\w+)"), ("instance", r"^(?:derive\s+)?instance\s+(\w+)")],
        package: r"^module\s+([\w.]+)"
    }
    "rescript" "ReScript / ReasonML source" "text/x-rescript" ["resi", "re", "rei"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"`",
        imports: [r"^\s*open\s+([\w.]+)", r#"^\s*@module\("([^"]+)"\)"#],
        symbols: [("value", r"^(?:let|and)\s+(?:rec\s+)?(\w+)"), ("type", r"^type\s+(?:rec\s+)?(\w+)"), ("module", r"^module\s+(?:type\s+)?(\w+)"), ("external", r"^(?:@\w+(?:\([^)]*\))?\s+)*external\s+(\w+)")],
        package: ""
    }
    "coffeescript" "CoffeeScript source" "text/x-coffeescript" ["coffee", "litcoffee"] {
        line: ["#"], block: [("###", "###")], quotes: b"\"'`",
        imports: [r#"(?-u:\b)require\s*\(?\s*['"]([^'"]+)['"]"#, r#"^\s*import\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]"#],
        symbols: [("class", r"^(?:export\s+)?class\s+([\w.@]+)"), ("function", r"^(?:export\s+)?([\w.@]+)\s*[=:]\s*(?:\([^)]*\)\s*)?[-=]>")],
        package: ""
    }
    "haxe" "Haxe source" "text/x-haxe" ["hx"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r"^\s*(?:import|using)\s+([\w.*]+)\s*;"],
        symbols: [("type", r"^(?:(?:private|extern|final|@:\w+(?:\([^)]*\))?)\s+)*(?:class|interface|enum|typedef|abstract)\s+(\w+)"), ("function", r"^\s{0,8}(?:(?:public|private|static|override|inline|dynamic|macro|extern)\s+)*function\s+(\w+)")],
        package: r"^\s*package\s+([\w.]+)\s*;"
    }
    "tcl" "Tcl source" "text/x-tcl" ["tcl", "tk", "tm", "itcl"] {
        line: ["#"], block: [], quotes: b"\"",
        imports: [r"^\s*package\s+require\s+(?:-exact\s+)?([\w:]+)", r"^\s*source\s+(\S+)"],
        symbols: [("procedure", r"^\s*proc\s+([\w:]+)"), ("namespace", r"^\s*namespace\s+eval\s+([\w:]+)"), ("class", r"^\s*(?:oo::|itcl::)?class\s+create\s+([\w:]+)")],
        package: r"^\s*package\s+provide\s+([\w:]+)"
    }
    "awk" "AWK script" "text/x-awk" ["awk", "gawk", "mawk"] {
        line: ["#"], block: [], quotes: b"\"",
        imports: [r#"^@(?:include|load)\s+"([^"]+)""#],
        symbols: [("function", r"^\s*func(?:tion)?\s+(\w+)"), ("pattern", r"^(BEGIN(?:FILE)?|END(?:FILE)?)(?-u:\b)")],
        package: ""
    }
    "sed" "sed script" "text/x-sed" ["sed"] {
        line: ["#"], block: [], quotes: b"",
        imports: [],
        symbols: [("label", r"^\s*:\s*(\w+)\s*$")],
        package: ""
    }
    "solidity" "Solidity source" "text/x-solidity" ["sol"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"^\s*import\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]"#],
        symbols: [("contract", r"^\s*(?:abstract\s+)?(?:contract|interface|library)\s+(\w+)"), ("function", r"^\s+function\s+(\w+)"), ("event", r"^\s+event\s+(\w+)"), ("modifier", r"^\s+modifier\s+(\w+)"), ("pragma", r"^pragma\s+solidity\s+([^;]+);")],
        package: ""
    }
    "move" "Move source" "text/x-move" ["move"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r"^\s*use\s+([\w:]+)"],
        symbols: [("function", r"^\s*(?:public(?:\([^)]*\))?\s+)?(?:entry\s+|native\s+|inline\s+)*fun\s+(\w+)"), ("struct", r"^\s*(?:public\s+)?struct\s+(\w+)")],
        package: r"^\s*module\s+([\w:]+)"
    }
    "cairo" "Cairo source" "text/x-cairo" ["cairo"] {
        line: ["//"], block: [], quotes: b"\"'",
        imports: [r"^\s*use\s+([\w:]+)", r"^from\s+([\w.]+)\s+import(?-u:\b)"],
        symbols: [("function", r"^\s*(?:pub\s+)?fn\s+(\w+)"), ("function", r"^func\s+(\w+)"), ("struct", r"^\s*(?:pub\s+)?struct\s+(\w+)"), ("trait", r"^\s*(?:pub\s+)?trait\s+(\w+)"), ("module", r"^\s*(?:pub\s+)?mod\s+(\w+)")],
        package: ""
    }
    "vyper" "Vyper source" "text/x-vyper" ["vy", "vyi"] {
        line: ["#"], block: [("\"\"\"", "\"\"\""), ("'''", "'''")], quotes: b"\"'",
        imports: [r"^\s*import\s+([\w.]+)", r"^\s*from\s+([\w.]+)\s+import(?-u:\b)"],
        symbols: [("function", r"^def\s+(\w+)"), ("event", r"^event\s+(\w+)"), ("struct", r"^struct\s+(\w+)"), ("interface", r"^interface\s+(\w+)"), ("pragma", r"^#\s*(?:@version|pragma\s+version)\s+(.+?)\s*$")],
        package: ""
    }
    "verilog" "Verilog / SystemVerilog source" "text/x-verilog" ["v", "sv", "svh", "vh"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r#"^\s*`include\s+"([^"]+)""#, r"^\s*import\s+([\w:*]+)\s*;"],
        symbols: [("module", r"^\s*(?:macro)?module\s+(?:automatic\s+)?(\w+)"), ("interface", r"^\s*interface\s+(?:class\s+)?(\w+)"), ("class", r"^\s*(?:virtual\s+)?class\s+(\w+)"), ("function", r"^\s*(?:virtual\s+|static\s+|automatic\s+)*(?:function|task)\s+(?:automatic\s+)?(?:[\w\[\]:]+\s+)*?(\w+)\s*[(;]")],
        package: r"^\s*package\s+(\w+)\s*;"
    }
    "vhdl" "VHDL source" "text/x-vhdl" ["vhdl"] {
        line: ["--"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r"(?i)^\s*use\s+([\w.]+)", r"(?i)^\s*library\s+([\w, ]+);"],
        symbols: [("entity", r"(?i)^\s*entity\s+(\w+)\s+is"), ("architecture", r"(?i)^\s*architecture\s+(\w+)\s+of"), ("component", r"(?i)^\s*component\s+(\w+)"), ("process", r"(?i)^\s*(\w+)\s*:\s*process"), ("subprogram", r"(?i)^\s*(?:pure\s+|impure\s+)?(?:function|procedure)\s+(\w+)")],
        package: r"(?i)^\s*package\s+(?:body\s+)?(\w+)\s+is"
    }
    "opencl" "OpenCL" "text/x-opencl" [] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"^\s*#\s*include\s*[<"]([^>"]+)[>"]"#],
        symbols: [("kernel", r"(?:__kernel|kernel)\s+void\s+(\w+)\s*\("), ("function", r"^[A-Za-z_][\w \t\*]*?(?-u:\b)([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{?\s*$")],
        package: ""
    }
    "glsl" "GLSL shader" "text/x-glsl" ["glsl", "vert", "frag", "geom", "comp", "tesc", "tese", "rgen", "rchit", "rmiss"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r#"^\s*#\s*include\s+[<"]([^>"]+)[>"]"#, r"^\s*#\s*extension\s+(\w+)"],
        symbols: [("function", r"^[A-Za-z_][\w \t]*?(?-u:\b)([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{?\s*$"), ("uniform", r"^\s*(?:layout\s*\([^)]*\)\s*)?uniform\s+(?:\w+\s+)*?(\w+)\s*(?:\[[^\]]*\])?\s*[;{]"), ("input", r"^\s*(?:layout\s*\([^)]*\)\s*)?(?:flat\s+|smooth\s+)?in\s+\w+\s+(\w+)\s*;"), ("output", r"^\s*(?:layout\s*\([^)]*\)\s*)?out\s+\w+\s+(\w+)\s*;"), ("version", r"^\s*#\s*version\s+(\d+(?:[ \t]+\w+)?)")],
        package: ""
    }
    "hlsl" "HLSL shader" "text/x-hlsl" ["hlsl", "hlsli", "fx", "fxh"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r#"^\s*#\s*include\s+[<"]([^>"]+)[>"]"#],
        symbols: [("function", r"^[A-Za-z_][\w \t]*?(?-u:\b)([A-Za-z_]\w*)\s*\([^;{]*\)\s*(?::\s*\w+\s*)?\{?\s*$"), ("cbuffer", r"^\s*(?:cbuffer|tbuffer)\s+(\w+)"), ("struct", r"^\s*struct\s+(\w+)"), ("technique", r"^\s*technique(?:10|11)?\s+(\w+)")],
        package: ""
    }
    "wgsl" "WGSL shader" "text/wgsl" ["wgsl"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r"^\s*enable\s+([\w, ]+)\s*;"],
        symbols: [("function", r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*fn\s+(\w+)"), ("struct", r"^\s*struct\s+(\w+)"), ("entry_point", r"@(vertex|fragment|compute)(?-u:\b)"), ("binding", r"^\s*@group\(\d+\)\s*@binding\(\d+\)\s*var(?:<[^>]*>)?\s+(\w+)")],
        package: ""
    }
    "metal" "Metal shader" "text/x-metal" ["metal"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"^\s*#\s*include\s*[<"]([^>"]+)[>"]"#],
        symbols: [("shader", r"^\s*(?:\[\[[^\]]*\]\]\s*)?(?:kernel|vertex|fragment)\s+[\w:<>]+\s+(\w+)\s*\("), ("struct", r"^\s*struct\s+(\w+)")],
        package: r"^\s*namespace\s+(\w+)"
    }
    "apex" "Apex source" "text/x-apex" ["cls", "trigger", "apex"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"'",
        imports: [],
        symbols: [("class", r"(?i)^\s*(?:@\w+\s+)*(?:(?:public|private|global|protected|virtual|abstract|with\s+sharing|without\s+sharing|inherited\s+sharing)\s+)*(?:class|interface|enum)\s+(\w+)"), ("trigger", r"(?i)^\s*trigger\s+(\w+)\s+on"), ("trigger_object", r"(?i)^\s*trigger\s+\w+\s+on\s+(\w+)"), ("method", r"(?i)^\s+(?:@\w+\s+)*(?:(?:public|private|global|protected|static|override|virtual|webservice)\s+)+[\w<>,.\[\]]+\s+(\w+)\s*\(")],
        package: ""
    }
    "abap" "ABAP source" "text/x-abap" ["abap"] {
        line: ["*", "\""], block: [], quotes: b"'`|",
        imports: [r"(?i)^\s*INCLUDE\s+([\w/]+)\s*\."],
        symbols: [("class", r"(?i)^\s*CLASS\s+([\w/]+)\s+(?:DEFINITION|IMPLEMENTATION)"), ("method", r"(?i)^\s*METHOD\s+([\w/~]+)\s*\."), ("form", r"(?i)^\s*FORM\s+([\w/]+)"), ("function", r"(?i)^\s*FUNCTION\s+([\w/]+)\s*\."), ("interface", r"(?i)^\s*INTERFACE\s+([\w/]+)\s")],
        package: r"(?i)^\s*(?:REPORT|PROGRAM|FUNCTION-POOL|CLASS-POOL)\s+([\w/]+)"
    }
    "smalltalk" "Smalltalk source" "text/x-smalltalk" ["st"] {
        line: [], block: [("\"", "\"")], quotes: b"'",
        imports: [],
        symbols: [("class", r"subclass:\s*#(\w+)"), ("class", r"^Class\s*\{\s*#name\s*:\s*#?'?(\w+)"), ("method_category", r"methodsFor:\s*'([^']+)'"), ("method", r"^\w+(?:\s+class)?\s*>>\s*(\w+:?)")],
        package: r"(?:category|package)\s*:\s*[#']*([\w-]+)"
    }
    "raku" "Raku source" "text/x-raku" ["raku", "rakumod", "rakutest", "p6", "pm6"] {
        line: ["#"], block: [("#`(", ")")], quotes: b"\"'",
        imports: [r"^\s*(?:use|need|require)\s+([A-Za-z][\w:]*)"],
        symbols: [("routine", r"^\s*(?:(?:multi|proto|our|my)\s+)*(?:sub|method|submethod)\s+([\w-]+)"), ("type", r"^\s*(?:unit\s+|my\s+|our\s+)?(?:class|role|grammar|module|package)\s+([\w:]+)"), ("token", r"^\s*(?:token|rule|regex)\s+([\w-]+)")],
        package: ""
    }
    "starlark" "Starlark / Bazel" "text/x-starlark" ["bzl", "star", "sky", "bazel"] {
        line: ["#"], block: [("\"\"\"", "\"\"\"")], quotes: b"\"'",
        imports: [r#"^load\(\s*"([^"]+)""#],
        symbols: [("function", r"^def\s+(\w+)"), ("target", r#"^\s+name\s*=\s*"([^"]+)""#), ("rule", r"^(\w+)\s*\(\s*$"), ("rule", r"^(\w+)\s*\(\s*name\s*=")],
        package: ""
    }
    "meson" "Meson build file" "text/x-meson" [] {
        line: ["#"], block: [], quotes: b"'",
        imports: [r"(?-u:\b)dependency\(\s*'([^']+)'", r"(?-u:\b)subdir\(\s*'([^']+)'"],
        symbols: [("target", r"(?-u:\b)(?:executable|library|shared_library|static_library|both_libraries|shared_module|jar|custom_target)\(\s*'([^']+)'"), ("test", r"(?-u:\b)test\(\s*'([^']+)'"), ("option", r"^option\(\s*'([^']+)'")],
        package: r"^project\(\s*'([^']+)'"
    }
    "ninja" "Ninja build file" "text/x-ninja" ["ninja"] {
        line: ["#"], block: [], quotes: b"",
        imports: [r"^(?:include|subninja)\s+(\S+)"],
        symbols: [("rule", r"^rule\s+(\S+)"), ("pool", r"^pool\s+(\S+)"), ("default", r"^default\s+(\S+)"), ("build", r"^build\s+([^:$\s]+)")],
        package: ""
    }
    "autohotkey" "AutoHotkey script" "text/x-autohotkey" ["ahk", "ahk2"] {
        line: [";"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r"(?i)^\s*#Include(?:Again)?\s+(?:\*i\s+)?(\S+)"],
        symbols: [("function", r"^(\w+)\([^)]*\)\s*\{?\s*$"), ("hotkey", r"^([^\s:;][^\s:]*)::"), ("label", r"^(\w+):\s*$"), ("class", r"(?i)^class\s+(\w+)")],
        package: ""
    }
    "autoit" "AutoIt script" "text/x-autoit" ["au3"] {
        line: [";"], block: [("#cs", "#ce"), ("#comments-start", "#comments-end")], quotes: b"\"'",
        imports: [r#"(?i)^\s*#include\s+[<"]([^>"]+)[>"]"#],
        symbols: [("function", r"(?i)^\s*Func\s+(\w+)")],
        package: ""
    }
    "gleam" "Gleam source" "text/x-gleam" ["gleam"] {
        line: ["//"], block: [], quotes: b"\"",
        imports: [r"^import\s+([\w/]+)"],
        symbols: [("function", r"^(?:pub\s+)?fn\s+(\w+)"), ("type", r"^(?:pub\s+)?(?:opaque\s+)?type\s+(\w+)"), ("const", r"^(?:pub\s+)?const\s+(\w+)")],
        package: ""
    }
    "roc" "Roc source" "text/x-roc" ["roc"] {
        line: ["#"], block: [], quotes: b"\"'",
        imports: [r"^\s*import\s+([\w.]+)"],
        symbols: [("function", r"^([a-z]\w*)\s*:\s"), ("header", r"^(app|module|package|platform|interface|hosted)(?-u:\b)")],
        package: ""
    }
    "unison" "Unison source" "text/x-unison" ["u"] {
        line: ["--"], block: [("{-", "-}")], quotes: b"\"",
        imports: [r"^\s*use\s+([\w.]+)"],
        symbols: [("term", r"^([a-z][\w']*)\s*:\s"), ("type", r"^(?:structural\s+|unique\s+)?(?:type|ability)\s+(\w+)")],
        package: ""
    }
    "mojo" "Mojo source" "text/x-mojo" ["mojo", "🔥"] {
        line: ["#"], block: [("\"\"\"", "\"\"\""), ("'''", "'''")], quotes: b"\"'",
        imports: [r"^\s*import\s+([\w.]+)", r"^\s*from\s+([\w.]+)\s+import(?-u:\b)"],
        symbols: [("function", r"^\s{0,4}(?:async\s+)?(?:def|fn)\s+(\w+)"), ("type", r"^(?:struct|trait|class)\s+(\w+)")],
        package: ""
    }
    "qsharp" "Q# source" "text/x-qsharp" [] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r"^\s*(?:open|import)\s+([\w.]+)"],
        symbols: [("operation", r"^\s*(?:internal\s+)?operation\s+(\w+)"), ("function", r"^\s*(?:internal\s+)?function\s+(\w+)"), ("type", r"^\s*(?:newtype|struct)\s+(\w+)")],
        package: r"^\s*namespace\s+([\w.]+)"
    }
    "openqasm" "OpenQASM source" "text/x-qasm" ["qasm"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r#"^\s*include\s+"([^"]+)""#],
        symbols: [("gate", r"^\s*gate\s+(\w+)"), ("register", r"^\s*(?:qreg|creg)\s+(\w+)"), ("register", r"^\s*(?:qubit|bit)(?:\[\d+\])?\s+(\w+)\s*;"), ("subroutine", r"^\s*def\s+(\w+)"), ("version", r"^\s*OPENQASM\s+([\d.]+)")],
        package: ""
    }
    "arduino" "Arduino sketch" "text/x-arduino" ["ino", "pde"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"^\s*#\s*include\s*[<"]([^>"]+)[>"]"#],
        symbols: [("function", r"^[A-Za-z_][\w \t\*&:<>,]*?(?-u:\b)([A-Za-z_][\w:~]*)\s*\([^;{]*\)\s*\{?\s*$"), ("class", r"^(?:class|struct)\s+(\w+)"), ("macro", r"^#\s*define\s+(\w+)")],
        package: ""
    }
    "llvm_ir" "LLVM IR" "text/x-llvm" ["ll"] {
        line: [";"], block: [], quotes: b"\"",
        imports: [],
        symbols: [("function", r#"^define\s[^@\n]*@("[^"]+"|[\w.$-]+)"#), ("declaration", r#"^declare\s[^@\n]*@("[^"]+"|[\w.$-]+)"#), ("global", r"^@([\w.$-]+)\s*="), ("type", r"^%([\w.$-]+)\s*=\s*type"), ("target_triple", r#"^target\s+triple\s*=\s*"([^"]+)""#)],
        package: ""
    }
    "wat" "WebAssembly text" "text/x-wat" ["wat", "wast"] {
        line: [";;"], block: [("(;", ";)")], quotes: b"\"",
        imports: [r#"\(import\s+"([^"]+)""#],
        symbols: [("function", r"\(func\s+(\$[^\s()]+)"), ("export", r#"\(export\s+"([^"]+)""#), ("memory", r"\(memory\s+(\$[^\s()]+)"), ("global", r"\(global\s+(\$[^\s()]+)")],
        package: r"^\s*\(module\s+(\$[^\s()]+)"
    }
    "antlr" "ANTLR grammar" "text/x-antlr" ["g4"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"'",
        imports: [r"^\s*import\s+([\w,\s]+);"],
        symbols: [("parser_rule", r"^([a-z]\w*)\s*(?::|$)"), ("lexer_rule", r"^(?:fragment\s+)?([A-Z]\w*)\s*(?::|$)")],
        package: r"^\s*(?:lexer\s+|parser\s+)?grammar\s+(\w+)\s*;"
    }
    "peg" "PEG grammar" "text/x-peg" ["peg", "pegjs", "peggy"] {
        line: ["#", "//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [],
        symbols: [("rule", r#"^(\w+)\s*(?:"[^"]*"\s*)?(?:<-|=|←)"#)],
        package: ""
    }
    "yacc" "Yacc / Bison grammar" "text/x-yacc" ["y", "yy", "ypp", "yxx"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"^\s*#\s*include\s*[<"]([^>"]+)[>"]"#],
        symbols: [("token", r"^%token\s+(?:<\w+>\s+)?(\w+)"), ("rule", r"^([a-zA-Z_][\w.]*)\s*:"), ("start", r"^%start\s+(\w+)")],
        package: ""
    }
    "lex" "Lex / Flex scanner" "text/x-lex" ["l", "lex", "lpp"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r#"^\s*#\s*include\s*[<"]([^>"]+)[>"]"#],
        symbols: [("start_condition", r"^%[xs]\s+(\w+)"), ("option", r"^%option\s+(\S+)")],
        package: ""
    }
    "puppet" "Puppet manifest" "text/x-puppet" [] {
        line: ["#"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r"^\s*(?:include|require|contain)\s+([\w:]+)"],
        symbols: [("class", r"^\s*class\s+([\w:]+)"), ("define", r"^\s*define\s+([\w:]+)"), ("node", r#"^\s*node\s+['"]?([\w.*-]+)"#), ("resource", r#"^\s*([\w:]+)\s*\{\s*['"$]"#)],
        package: ""
    }
    "plsql" "PL/SQL / T-SQL source" "text/x-plsql" ["plsql", "pkb", "pks", "tsql"] {
        line: ["--"], block: [("/*", "*/")], quotes: b"'",
        imports: [],
        symbols: [("procedure", r#"(?i)^\s*(?:CREATE\s+(?:OR\s+(?:REPLACE|ALTER)\s+)?(?:EDITIONABLE\s+|NONEDITIONABLE\s+)?)?PROCEDURE\s+([\w."\[\]]+)"#), ("function", r#"(?i)^\s*(?:CREATE\s+(?:OR\s+(?:REPLACE|ALTER)\s+)?(?:EDITIONABLE\s+|NONEDITIONABLE\s+)?)?FUNCTION\s+([\w."\[\]]+)"#), ("package", r#"(?i)^\s*CREATE\s+(?:OR\s+REPLACE\s+)?PACKAGE\s+(?:BODY\s+)?([\w."]+)"#), ("trigger", r#"(?i)^\s*CREATE\s+(?:OR\s+(?:REPLACE|ALTER)\s+)?TRIGGER\s+([\w."\[\]]+)"#), ("view", r#"(?i)^\s*CREATE\s+(?:OR\s+(?:REPLACE|ALTER)\s+)?VIEW\s+([\w."\[\]]+)"#), ("table", r#"(?i)^\s*CREATE\s+TABLE\s+([\w."\[\]#]+)"#)],
        package: ""
    }
    "go_template" "Go template" "text/x-go-template" ["tmpl", "gotmpl"] {
        line: [], block: [("{{/*", "*/}}"), ("{{- /*", "*/ -}}")], quotes: b"",
        imports: [r#"\{\{-?\s*template\s+"([^"]+)""#],
        symbols: [("define", r#"\{\{-?\s*define\s+"([^"]+)""#), ("block", r#"\{\{-?\s*block\s+"([^"]+)""#)],
        package: ""
    }
    "handlebars" "Handlebars / Mustache template" "text/x-handlebars-template" ["hbs", "handlebars", "mustache"] {
        line: [], block: [("{{!--", "--}}"), ("{{!", "}}"), ("<!--", "-->")], quotes: b"",
        imports: [r"\{\{>\s*([\w/.-]+)"],
        symbols: [("helper", r"\{\{#(\w+)"), ("variable", r"\{\{\{?\s*([\w.]+)\s*\}\}")],
        package: ""
    }
    "pug" "Pug template" "text/x-pug" ["pug", "jade"] {
        line: ["//-", "//"], block: [], quotes: b"\"'",
        imports: [r"^\s*(?:include|extends)\s+(\S+)"],
        symbols: [("mixin", r"^\s*mixin\s+([\w-]+)"), ("block", r"^\s*block\s+(?:append\s+|prepend\s+)?([\w-]+)")],
        package: ""
    }
    "vim_script" "Vim script" "text/x-vim" ["vim", "vimrc"] {
        line: ["\""], block: [], quotes: b"'\"",
        imports: [r"^\s*(?:source|runtime!?)\s+(\S+)", r"^\s*(?:Plug|Plugin|packadd!?)\s+'?([^'\s]+)"],
        symbols: [("function", r"^\s*(?:fu|fun|func|function|def)!?\s+([\w:#.<>]+)"), ("command", r"^\s*com(?:mand)?!?\s+(?:-\S+\s+)*(\w+)"), ("autocmd_group", r"^\s*aug(?:roup)?\s+(\w+)"), ("mapping", r"^\s*[nvxoic]?(?:nore)?map\s+(?:<\w+>\s+)*(\S+)")],
        package: ""
    }
    "nushell" "Nushell script" "text/x-nushell" ["nu"] {
        line: ["#"], block: [], quotes: b"\"'`",
        imports: [r"^\s*(?:use|source|overlay\s+use)\s+(\S+)"],
        symbols: [("command", r#"^\s*(?:export\s+)?def(?:-env)?\s+(?:--\w+\s+)*['"]?([\w -]+?)['"]?\s*\["#), ("alias", r"^\s*(?:export\s+)?alias\s+([\w-]+)")],
        package: ""
    }
    "elvish" "Elvish script" "text/x-elvish" ["elv"] {
        line: ["#"], block: [], quotes: b"\"'",
        imports: [r"^\s*use\s+(\S+)"],
        symbols: [("function", r"^\s*fn\s+([\w-]+)"), ("variable", r"^\s*var\s+([\w-]+)")],
        package: ""
    }
    "rego" "Rego policy" "text/x-rego" ["rego"] {
        line: ["#"], block: [], quotes: b"\"`",
        imports: [r"^\s*import\s+([\w.]+)"],
        symbols: [("rule", r"^([a-z_]\w*)(?:\s+(?:contains|if)(?-u:\b)|\s*(?:\[[^\]]*\])?\s*(?::?=|\{))")],
        package: r"^package\s+([\w.]+)"
    }
    "bicep" "Bicep template" "text/x-bicep" ["bicep", "bicepparam"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"'",
        imports: [r"^\s*import\s+(?:[^'\n]*\s+from\s+)?'([^']+)'", r"^\s*module\s+\w+\s+'([^']+)'"],
        symbols: [("parameter", r"^\s*param\s+(\w+)"), ("variable", r"^\s*var\s+(\w+)"), ("resource", r"^\s*resource\s+(\w+)\s+'"), ("resource_type", r"^\s*resource\s+\w+\s+'([^'@]+)"), ("output", r"^\s*output\s+(\w+)"), ("module", r"^\s*module\s+(\w+)")],
        package: r"^\s*targetScope\s*=\s*'(\w+)'"
    }
    "lean" "Lean source" "text/x-lean" ["lean"] {
        line: ["--"], block: [("/-", "-/")], quotes: b"\"",
        imports: [r"^import\s+([\w.]+)"],
        symbols: [("theorem", r"^\s*(?:@\[[^\]]*\]\s*)?(?:private\s+|protected\s+|noncomputable\s+)*(?:theorem|lemma)\s+([\w.']+)"), ("definition", r"^\s*(?:@\[[^\]]*\]\s*)?(?:private\s+|protected\s+|noncomputable\s+|partial\s+)*(?:def|abbrev|instance|axiom)\s+([\w.']+)"), ("type", r"^\s*(?:structure|inductive|class)\s+([\w.']+)")],
        package: r"^namespace\s+([\w.]+)"
    }
    "coq" "Coq / Rocq source" "text/x-coq" [] {
        line: [], block: [("(*", "*)")], quotes: b"\"",
        imports: [r"^\s*(?:From\s+\S+\s+)?Require\s+(?:Import\s+|Export\s+)?(\w+(?:\.\w+)*)"],
        symbols: [("theorem", r"^\s*(?:Theorem|Lemma|Corollary|Proposition|Fact|Remark|Example)\s+([\w']+)"), ("definition", r"^\s*(?:Definition|Fixpoint|CoFixpoint|Function|Axiom|Parameter|Variable)\s+([\w']+)"), ("type", r"^\s*(?:Inductive|CoInductive|Record|Structure|Class)\s+([\w']+)")],
        package: r"^\s*Module\s+(?:Type\s+)?(\w+)"
    }
    "agda" "Agda source" "text/x-agda" ["agda", "lagda"] {
        line: ["--"], block: [("{-", "-}")], quotes: b"\"",
        imports: [r"^\s*(?:open\s+)?import\s+([\w.]+)"],
        symbols: [("definition", r"^([^\s:(){}]+)\s*:\s"), ("type", r"^\s*(?:data|record)\s+(\S+)")],
        package: r"^module\s+([\w.]+)"
    }
    "idris" "Idris source" "text/x-idris" ["idr", "lidr"] {
        line: ["|||", "--"], block: [("{-", "-}")], quotes: b"\"",
        imports: [r"^import\s+(?:public\s+)?([\w.]+)"],
        symbols: [("function", r"^([a-z][\w']*)\s*:\s"), ("type", r"^(?:public\s+export\s+|export\s+)?(?:data|record|interface)\s+(\w+)")],
        package: r"^module\s+([\w.]+)"
    }
    "isabelle" "Isabelle theory" "text/x-isabelle" ["thy"] {
        line: [], block: [("(*", "*)")], quotes: b"\"",
        imports: [r"^\s*imports\s+(.+?)\s*$"],
        symbols: [("theorem", r"^\s*(?:theorem|lemma|corollary|proposition)\s+(\w+)"), ("definition", r"^\s*(?:definition|fun|function|primrec|abbreviation)\s+(\w+)"), ("type", r"^\s*(?:datatype|record|typedecl|type_synonym)\s+(?:\('[^)]*\)\s+|'\w+\s+)?(\w+)")],
        package: r"^\s*theory\s+(\w+)"
    }
    "tla" "TLA+ specification" "text/x-tla" ["tla"] {
        line: ["\\*"], block: [("(*", "*)")], quotes: b"\"",
        imports: [r"^EXTENDS\s+([\w,\s]+?)\s*$"],
        symbols: [("definition", r"^([A-Za-z]\w*)(?:\([^)]*\))?\s*=="), ("constant", r"^CONSTANTS?\s+([\w, ]+)"), ("variable", r"^VARIABLES?\s+([\w, ]+)"), ("theorem", r"^THEOREM\s+(\w+)")],
        package: r"^-{4,}\s*MODULE\s+(\w+)"
    }
    "alloy" "Alloy model" "text/x-alloy" ["als"] {
        line: ["--", "//"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r"^open\s+([\w/]+)"],
        symbols: [("signature", r"^\s*(?:abstract\s+|one\s+|lone\s+|some\s+)*sig\s+(\w+)"), ("fact", r"^\s*fact\s+(\w+)"), ("predicate", r"^\s*pred\s+(?:\w+\.)?(\w+)"), ("function", r"^\s*fun\s+(?:\w+\.)?(\w+)"), ("assertion", r"^\s*assert\s+(\w+)")],
        package: r"^module\s+([\w/]+)"
    }
    "ballerina" "Ballerina source" "text/x-ballerina" ["bal"] {
        line: ["//"], block: [], quotes: b"\"`",
        imports: [r"^import\s+([\w./]+)"],
        symbols: [("function", r"^\s*(?:public\s+|isolated\s+|remote\s+|resource\s+)*function\s+(?:\w+\s+)?(\w+)\s*\("), ("service", r"^\s*service\s+(\S+)\s+on"), ("type", r"^(?:public\s+)?type\s+(\w+)")],
        package: ""
    }
    "pony" "Pony source" "text/x-pony" ["pony"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"'",
        imports: [r#"^use\s+(?:\w+\s*=\s*)?"([^"]+)""#],
        symbols: [("type", r"^(?:actor|class|primitive|trait|interface|struct|type)\s+(\w+)"), ("method", r"^\s+(?:fun|be|new)\s+(?:ref\s+|box\s+|val\s+|iso\s+|tag\s+|trn\s+)?(\w+)")],
        package: ""
    }
    "janet" "Janet source" "text/x-janet" ["janet"] {
        line: ["#"], block: [], quotes: b"\"`",
        imports: [r"\(import\s+\.?/?([\w/.-]+)", r"\(use\s+([\w/.-]+)"],
        symbols: [("function", r"^\(defn-?\s+([^\s()]+)"), ("macro", r"^\(defmacro-?\s+([^\s()]+)"), ("variable", r"^\((?:def|var)-?\s+([^\s()]+)")],
        package: ""
    }
    "fennel" "Fennel source" "text/x-fennel" ["fnl"] {
        line: [";"], block: [], quotes: b"\"",
        imports: [r#"\(require\s+:?["']?([\w.-]+)"#, r"\(import-macros\s+\S+\s+:?([\w.-]+)"],
        symbols: [("function", r"^\((?:fn|λ|lambda)\s+([^\s()\[\]]+)"), ("macro", r"^\(macro\s+([^\s()]+)"), ("variable", r"^\((?:local|global|var)\s+([^\s()\[\]{}]+)")],
        package: ""
    }
    "hy" "Hy source" "text/x-hy" ["hy"] {
        line: [";"], block: [], quotes: b"\"",
        imports: [r"\(import\s+([\w.]+)", r"\(require\s+([\w.]+)"],
        symbols: [("function", r"^\(defn\s+(?:\[[^\]]*\]\s*)?([^\s()\[\]]+)"), ("macro", r"^\(defmacro\s+([^\s()]+)"), ("class", r"^\(defclass\s+([^\s()]+)")],
        package: ""
    }
    "forth" "Forth source" "text/x-forth" ["fth", "4th", "forth", "frt"] {
        line: ["\\"], block: [("( ", ")")], quotes: b"\"",
        imports: [r"(?i)^\s*(?:include|require)\s+(\S+)"],
        symbols: [("word", r"^:\s+(\S+)"), ("variable", r"(?i)^(?:variable|constant|value|create)\s+(\S+)")],
        package: ""
    }
    "apl" "APL source" "text/x-apl" ["apl", "dyalog", "aplf", "apln"] {
        line: ["⍝"], block: [], quotes: b"'",
        imports: [],
        symbols: [("function", r"^\s*(\w+)\s*←\s*\{"), ("tradfn", r"^\s*∇\s*(.+?)\s*$")],
        package: r"^\s*:Namespace\s+(\w+)"
    }
    "j_lang" "J source" "text/x-j" ["ijs", "ijt"] {
        line: ["NB."], block: [], quotes: b"'",
        imports: [r"^\s*(?:require|load)\s+'([^']+)'"],
        symbols: [("definition", r"^\s*(\w+)\s*=:\s")],
        package: r"^\s*coclass\s+'(\w+)'"
    }
    "gdscript" "GDScript source" "text/x-gdscript" ["gd"] {
        line: ["#"], block: [], quotes: b"\"'",
        imports: [r#"(?:preload|load)\(\s*"([^"]+)""#],
        symbols: [("function", r"^(?:static\s+)?func\s+(\w+)"), ("signal", r"^signal\s+(\w+)"), ("class", r"^class(?:_name)?\s+(\w+)"), ("extends", r#"^extends\s+"?([\w./:]+)"#), ("export", r"^@export\w*(?:\([^)]*\))?\s+var\s+(\w+)")],
        package: ""
    }
    "shaderlab" "Unity ShaderLab" "text/x-shaderlab" ["shader"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r#"^\s*#include\s+"([^"]+)""#, r#"UsePass\s+"([^"]+)""#],
        symbols: [("shader", r#"^\s*Shader\s+"([^"]+)""#), ("pass", r#"^\s*Name\s+"([^"]+)""#), ("property", r#"^\s*(?:\[[^\]]*\]\s*)*(_\w+)\s*\(\s*""#), ("pragma", r"^\s*#pragma\s+(\w+[ \t]+\w+)"), ("fallback", r#"(?i)^\s*Fallback\s+"([^"]+)""#)],
        package: ""
    }
    "plc_st" "IEC 61131-3 Structured Text" "text/x-iecst" ["scl"] {
        line: ["//"], block: [("(*", "*)")], quotes: b"'\"",
        imports: [r"(?i)^\s*USING\s+([\w.]+)"],
        symbols: [("program", r"(?i)^\s*PROGRAM\s+(\w+)"), ("function_block", r#"(?i)^\s*FUNCTION_BLOCK\s+(?:PUBLIC\s+|FINAL\s+|ABSTRACT\s+)?"?(\w+)"#), ("function", r#"(?i)^\s*FUNCTION\s+"?(\w+)"#), ("type", r"(?i)^\s*TYPE\s+(\w+)"), ("method", r"(?i)^\s*METHOD\s+(?:PUBLIC\s+|PRIVATE\s+)?(\w+)")],
        package: r"(?i)^\s*NAMESPACE\s+([\w.]+)"
    }
    "max_patch" "Max patch" "application/x-max-patch" ["maxpat", "maxhelp"] {
        line: [], block: [], quotes: b"\"",
        imports: [],
        symbols: [("object", r#""maxclass"\s*:\s*"(\w+)""#)],
        package: ""
    }
    "pure_data" "Pure Data patch" "text/x-puredata" ["pd"] {
        line: [], block: [], quotes: b"",
        imports: [],
        symbols: [("object", r"^#X\s+obj\s+-?\d+\s+-?\d+\s+([^\s;]+)"), ("message", r"^#X\s+msg\s+-?\d+\s+-?\d+\s+((?:[^;\\]|\\.)+?)\s*;"), ("subpatch", r"^#N\s+canvas(?:\s+-?\d+){4}\s+([A-Za-z_][\w.-]*)\s")],
        package: ""
    }
    "yara" "YARA rules" "text/x-yara" ["yar", "yara"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"",
        imports: [r#"^\s*import\s+"([^"]+)""#, r#"^\s*include\s+"([^"]+)""#],
        symbols: [("rule", r"^\s*(?:private\s+|global\s+)*rule\s+(\w+)"), ("tag", r"^\s*(?:private\s+|global\s+)*rule\s+\w+\s*:\s*([\w ]+?)\s*\{?\s*$")],
        package: ""
    }
    "smithy" "Smithy model" "text/x-smithy" ["smithy"] {
        line: ["//"], block: [], quotes: b"\"",
        imports: [r"^\s*use\s+([\w.#]+)"],
        symbols: [("shape", r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:structure|union|service|operation|resource|string|integer|list|map|enum|intEnum|long|boolean|blob|timestamp|document|set|double|float|short|byte|bigInteger|bigDecimal)\s+(\w+)"), ("version", r#"^\$version\s*:\s*"([^"]+)""#)],
        package: r"^\s*namespace\s+([\w.]+)"
    }
    "avro_idl" "Avro IDL" "text/x-avro-idl" ["avdl"] {
        line: ["//"], block: [("/*", "*/")], quotes: b"\"`",
        imports: [r#"^\s*import\s+(?:idl|protocol|schema)\s+"([^"]+)""#],
        symbols: [("protocol", r"^\s*(?:@\w+\([^)]*\)\s*)*protocol\s+(\w+)"), ("record", r"^\s*(?:@\w+\([^)]*\)\s*)*(?:record|error)\s+(\w+)"), ("enum", r"^\s*(?:@\w+\([^)]*\)\s*)*enum\s+(\w+)"), ("fixed", r"^\s*fixed\s+(\w+)")],
        package: r#"@namespace\("([^"]+)"\)"#
    }
    "applescript" "AppleScript source" "text/x-applescript" ["applescript"] {
        line: ["--", "#"], block: [("(*", "*)")], quotes: b"\"",
        imports: [r#"^\s*use\s+(?:script|framework)\s+"([^"]+)""#, r"^\s*use\s+(\w+)\s+version"],
        symbols: [("handler", r"^\s*on\s+(\w+)"), ("handler", r"^\s*to\s+(\w+)"), ("tell", r#"^\s*tell\s+application\s+"([^"]+)""#)],
        package: ""
    }
}

static META: ExtractorMeta =
    ExtractorMeta { id: "code.source", version: 1, cost: Cost::Scan, priority: 0, formats: FORMATS };

/// Interpreters named in shebang lines.
const INTERPRETERS: &[(&str, &str)] = &[
    ("python", "python"),
    ("python2", "python"),
    ("python3", "python"),
    ("pypy", "python"),
    ("node", "javascript"),
    ("nodejs", "javascript"),
    ("deno", "typescript"),
    ("bun", "typescript"),
    ("ts-node", "typescript"),
    ("sh", "shell"),
    ("bash", "shell"),
    ("zsh", "shell"),
    ("ksh", "shell"),
    ("dash", "shell"),
    ("fish", "shell"),
    ("ruby", "ruby"),
    ("perl", "perl"),
    ("php", "php"),
    ("pwsh", "powershell"),
    ("powershell", "powershell"),
    ("lua", "lua"),
    ("Rscript", "r"),
    ("julia", "julia"),
    ("elixir", "elixir"),
    ("escript", "erlang"),
    ("groovy", "groovy"),
    ("swift", "swift"),
    ("scala", "scala"),
    ("tclsh", "tcl"),
    ("wish", "tcl"),
    ("awk", "awk"),
    ("gawk", "awk"),
    ("mawk", "awk"),
    ("nawk", "awk"),
    ("sed", "sed"),
    ("raku", "raku"),
    ("perl6", "raku"),
    ("nu", "nushell"),
    ("elvish", "elvish"),
    ("janet", "janet"),
    ("fennel", "fennel"),
    ("hy", "hy"),
    ("crystal", "crystal"),
    ("nim", "nim"),
    ("racket", "scheme"),
    ("guile", "scheme"),
    ("csi", "scheme"),
    ("chez", "scheme"),
    ("sbcl", "lisp"),
    ("clisp", "lisp"),
    ("emacs", "lisp"),
    ("gforth", "forth"),
    ("swipl", "prolog"),
    ("octave", "matlab"),
    ("coffee", "coffeescript"),
    ("osascript", "applescript"),
    ("dart", "dart"),
    ("v", "vlang"),
    ("mojo", "mojo"),
];

/// File names that identify a language.
const NAMES: &[(&str, &str)] = &[
    ("CMakeLists.txt", "cmake"),
    ("Rakefile", "ruby"),
    ("Gemfile", "ruby"),
    ("Vagrantfile", "ruby"),
    ("Podfile", "ruby"),
    ("Jenkinsfile", "groovy"),
    (".bashrc", "shell"),
    (".bash_profile", "shell"),
    (".zshrc", "shell"),
    (".profile", "shell"),
    (".bash_logout", "shell"),
    (".zprofile", "shell"),
    (".zshenv", "shell"),
    (".zlogin", "shell"),
    (".kshrc", "shell"),
    ("BUILD", "starlark"),
    ("BUILD.bazel", "starlark"),
    ("WORKSPACE", "starlark"),
    ("WORKSPACE.bazel", "starlark"),
    ("BUCK", "starlark"),
    ("Tiltfile", "starlark"),
    ("meson.build", "meson"),
    ("meson_options.txt", "meson"),
    ("meson.options", "meson"),
    ("build.ninja", "ninja"),
    (".vimrc", "vim_script"),
    ("_vimrc", "vim_script"),
    ("vimrc", "vim_script"),
    (".gvimrc", "vim_script"),
    (".exrc", "vim_script"),
];

impl Extractor for SourceCode {
    fn meta(&self) -> &'static ExtractorMeta {
        &META
    }

    fn sniff(&self, probe: &Probe<'_>) -> Option<Sniff> {
        if let Some(name) = probe.name.map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n))
            && let Some((_, id)) = NAMES.iter().find(|(n, _)| *n == name)
        {
            return Some(Sniff { format: id, confidence: 0.9 });
        }
        let head = std::str::from_utf8(&probe.head[..probe.head.len().min(1024)])
            .or_else(|e| std::str::from_utf8(&probe.head[..e.valid_up_to()]))
            .ok()?;
        // `.cue` is also a CUE sheet (which has FILE and TRACK commands).
        if probe.extension == Some("cue") {
            let sheet = head.lines().any(|l| {
                let l = l.trim_start().to_ascii_uppercase();
                l.starts_with("FILE ") || l.starts_with("TRACK ")
            });
            return (!sheet).then_some(Sniff { format: "cuelang", confidence: 0.6 });
        }
        // `.m` is MATLAB / Octave unless it reads as Objective-C.
        if probe.extension == Some("m") {
            let objc = head.lines().any(|l| {
                let l = l.trim_start();
                l.starts_with("#import")
                    || l.starts_with("#include")
                    || l.starts_with("@interface")
                    || l.starts_with("@implementation")
                    || l.starts_with("@import")
            });
            return objc.then_some(Sniff { format: "objective_c", confidence: 0.9 });
        }
        // Extensions only these formats use, whose content other sniffers
        // would claim (Max patches are JSON; Smithy starts like a VCD file).
        match probe.extension.map(str::to_ascii_lowercase).as_deref() {
            Some("maxpat" | "maxhelp") => return Some(Sniff { format: "max_patch", confidence: 0.97 }),
            Some("smithy") => return Some(Sniff { format: "smithy", confidence: 0.97 }),
            _ => {}
        }
        if let Some(ext) = probe.extension.map(str::to_ascii_lowercase)
            && let Some(id) = shared_extension(&ext, head, probe.head)
        {
            return Some(Sniff { format: id, confidence: 0.9 });
        }
        if let Some(id) = shebang(head).and_then(|i| language_of_interpreter(&i)) {
            return Some(Sniff { format: id, confidence: 0.9 });
        }
        modeline(head).map(|id| Sniff { format: id, confidence: 0.85 })
    }

    fn extract(&self, src: &mut dyn Source, cx: &mut Context<'_>) -> Result<(), ExtractError> {
        let text = cx.read_text(src)?.text;
        let lang = LANGS.iter().find(|l| l.id == cx.format_id()).unwrap_or(&LANGS[0]);
        let compiled = compiled(lang);
        cx.emit_text(TextRole::Code, &text);
        let mut a = analyse(&text, lang, &compiled);
        cx.checkpoint()?;
        let name = src.name_hint().unwrap_or("").to_string();
        a.has_tests = looks_like_test(&name, &text);
        report(&a, &text, lang, cx);
        if lang.id == "latex" {
            super::latex::extract(&text, cx)?;
        }
        Ok(())
    }
}

crate::register_extractor!(SourceCode);

/// The language of a file whose extension several languages (or a binary
/// format) share, from its first lines; `None` leaves it to the extension.
fn shared_extension(ext: &str, head: &str, raw: &[u8]) -> Option<&'static str> {
    let text = !raw.is_empty() && !raw.contains(&0);
    let starts = |words: &[&str]| head.lines().any(|l| words.iter().any(|w| l.trim_start().starts_with(w)));
    let upper = || head.to_ascii_uppercase();
    match ext {
        // Verilog (the extension's owner), Coq / Rocq or V.
        "v" => {
            // V also has `module main`, without a port list.
            let verilog_module = head.lines().any(|l| {
                let l = l.trim_start();
                l.starts_with("module ") && (l.contains('(') || l.contains(';') || l.contains('#'))
            });
            if verilog_module
                || starts(&[
                    "endmodule",
                    "always",
                    "wire ",
                    "reg ",
                    "input ",
                    "output ",
                    "assign ",
                    "`timescale",
                    "`include",
                ])
            {
                None
            } else if starts(&[
                "Require ",
                "From ",
                "Theorem ",
                "Lemma ",
                "Proof.",
                "Inductive ",
                "Definition ",
                "Fixpoint ",
            ]) {
                Some("coq")
            } else if starts(&["fn ", "pub fn ", "import ", "struct ", "module main"]) {
                Some("vlang")
            } else {
                None
            }
        }
        // Common Lisp (the owner) or OpenCL.
        "cl" => (head.contains("__kernel") || head.contains("kernel void")).then_some("opencl"),
        // Pascal (the owner) or Puppet.
        "pp" => {
            let pascal = upper().lines().any(|l| {
                let l = l.trim_start();
                ["UNIT ", "PROGRAM ", "USES ", "BEGIN", "LIBRARY ", "INTERFACE", "{$MODE"]
                    .iter()
                    .any(|w| l.starts_with(w))
            });
            let puppet = starts(&["class ", "define ", "node ", "include ", "file {", "package {", "service {"])
                || head.contains("=>");
            (puppet && !pascal).then_some("puppet")
        }
        // Smalltalk (the owner) or IEC 61131-3 Structured Text.
        "st" => {
            let u = upper();
            (u.contains("END_VAR") || u.contains("FUNCTION_BLOCK") || u.contains("END_PROGRAM")).then_some("plc_st")
        }
        // Apex (the owner), a LaTeX class or a Visual Basic class module.
        "cls" => {
            if starts(&["\\NeedsTeXFormat", "\\ProvidesClass", "\\LoadClass", "%%"]) {
                Some("latex")
            } else if starts(&["VERSION 1.0 CLASS", "Attribute VB_"]) {
                Some("visual_basic")
            } else {
                None
            }
        }
        // Binary or playlist formats own these; PL/SQL is text with DDL.
        "pls" | "pck" => {
            let u = upper();
            let ddl =
                u.contains("CREATE ") && ["PROCEDURE", "PACKAGE", "FUNCTION", "TRIGGER"].iter().any(|w| u.contains(w));
            (text && !u.trim_start().starts_with("[PLAYLIST]") && ddl).then_some("plsql")
        }
        // Godot binary resources (`RSRC`) and Windows resources are binary.
        "res" => (text && !raw.starts_with(b"RSRC")).then_some("rescript"),
        // R qs serialisations are binary.
        "qs" => (text && (head.contains("namespace ") || head.contains("operation ") || head.contains("import Std")))
            .then_some("qsharp"),
        // Virtual hard disks are binary.
        "vhd" => {
            let u = upper();
            (text && (u.contains("ENTITY ") || u.contains("LIBRARY IEEE") || u.contains("ARCHITECTURE ")))
                .then_some("vhdl")
        }
        _ => None,
    }
}

fn shebang(head: &str) -> Option<String> {
    let line = head.lines().next()?.strip_prefix("#!")?.trim();
    let mut parts = line.split_whitespace();
    let program = parts.next()?;
    let program = program.rsplit('/').next().unwrap_or(program);
    // `#!/usr/bin/env -S python3 -u`
    let interpreter = if program == "env" { parts.find(|p| !p.starts_with('-'))? } else { program };
    Some(interpreter.to_string())
}

fn language_of_interpreter(interpreter: &str) -> Option<&'static str> {
    let base = interpreter.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS.iter().find(|(i, _)| *i == interpreter || *i == base).map(|(_, l)| *l)
}

/// Emacs `-*- mode: python -*-` or Vim `vim: set ft=ruby:` in the first or last lines.
fn modeline(head: &str) -> Option<&'static str> {
    let first: String = head.lines().take(3).collect::<Vec<_>>().join("\n").to_ascii_lowercase();
    let name = if let Some(m) = first.split("-*-").nth(1) {
        let m = m.trim();
        m.split(';').find_map(|p| p.trim().strip_prefix("mode:")).unwrap_or(m).trim().to_string()
    } else {
        let at = first.find("vim:").or_else(|| first.find("vi:"))?;
        let rest = &first[at..];
        rest.split([' ', ':'])
            .find_map(|p| p.strip_prefix("ft=").or_else(|| p.strip_prefix("filetype=")))
            .unwrap_or("")
            .to_string()
    };
    let id = match name.as_str() {
        "python" => "python",
        "ruby" => "ruby",
        "sh" | "bash" | "zsh" | "shell-script" => "shell",
        "perl" | "cperl" => "perl",
        "javascript" | "js" => "javascript",
        "typescript" | "ts" => "typescript",
        "c" => "c",
        "c++" | "cpp" => "cpp",
        "rust" => "rust",
        "go" => "go",
        "lua" => "lua",
        "php" => "php",
        "java" => "java",
        "tex" | "latex" => "latex",
        "cmake" => "cmake",
        "tcl" => "tcl",
        "vim" => "vim_script",
        "fortran" | "f90" => "fortran",
        "cobol" => "cobol",
        "pascal" | "delphi" => "pascal",
        "ada" => "ada",
        "lisp" | "emacs-lisp" | "common-lisp" => "lisp",
        "scheme" | "racket" => "scheme",
        "prolog" => "prolog",
        "verilog" | "systemverilog" => "verilog",
        "vhdl" => "vhdl",
        "glsl" => "glsl",
        "nim" => "nim",
        "awk" => "awk",
        "sed" => "sed",
        "raku" | "perl6" => "raku",
        "bzl" | "starlark" => "starlark",
        "meson" => "meson",
        "ninja" => "ninja",
        "coq" => "coq",
        "forth" => "forth",
        "yacc" | "bison" => "yacc",
        "lex" | "flex" => "lex",
        "puppet" => "puppet",
        _ => return None,
    };
    Some(id)
}

/// A language's patterns, compiled once.
struct Compiled {
    imports: Vec<Regex>,
    symbols: Vec<(&'static str, Regex)>,
    package: Option<Regex>,
}

fn compiled(lang: &'static Lang) -> Arc<Compiled> {
    static CACHE: LazyLock<Mutex<HashMap<&'static str, Arc<Compiled>>>> = LazyLock::new(Mutex::default);
    let lock = || CACHE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(c) = lock().get(lang.id) {
        return Arc::clone(c);
    }
    // Compile without holding the lock, so threads analysing other languages
    // do not wait on it; a thread that loses the race uses the winner's copy.
    let re = |p: &str| Regex::new(&format!("(?m){p}")).ok();
    let fresh = Arc::new(Compiled {
        imports: lang.imports.iter().filter_map(|p| re(p)).collect(),
        symbols: lang.symbols.iter().filter_map(|(k, p)| re(p).map(|r| (*k, r))).collect(),
        package: (!lang.package.is_empty()).then(|| re(lang.package)).flatten(),
    });
    Arc::clone(lock().entry(lang.id).or_insert(fresh))
}

#[derive(Default)]
struct Analysis {
    code: u64,
    comment: u64,
    blank: u64,
    /// Comment text before the first line of code.
    header: String,
    /// All comment text (capped).
    comments: String,
    imports: Vec<String>,
    import_count: usize,
    symbols: BTreeMap<&'static str, Vec<String>>,
    symbol_counts: BTreeMap<&'static str, u64>,
    package: Option<String>,
    longest_line: usize,
    has_tests: bool,
}

const MAX_LISTED: usize = 100;
const MAX_COMMENT_TEXT: usize = 256 * 1024;

fn analyse(text: &str, lang: &Lang, c: &Compiled) -> Analysis {
    let mut a = Analysis::default();
    let mut in_block: Option<&str> = None;
    let mut seen_code = false;
    for (n, line) in text.lines().enumerate() {
        a.longest_line = a.longest_line.max(line.len());
        let trimmed = line.trim();
        // The shebang is code, not documentation.
        if n == 0 && trimmed.starts_with("#!") {
            a.code += 1;
            continue;
        }
        if trimmed.is_empty() && in_block.is_none() {
            a.blank += 1;
            continue;
        }
        let (code, comment) = classify(line, lang, &mut in_block, &mut a.comments);
        if code {
            a.code += 1;
            seen_code = true;
        } else if comment {
            a.comment += 1;
            if !seen_code && a.header.len() < 16 * 1024 {
                a.header.push_str(strip_markers(trimmed));
                a.header.push('\n');
            }
        } else {
            a.blank += 1;
        }
    }
    let mut seen = std::collections::HashSet::new();
    for re in &c.imports {
        for cap in re.captures_iter(text) {
            if let Some(m) = cap.get(1) {
                for name in m.as_str().split(',').map(str::trim).filter(|n| !n.is_empty()) {
                    a.import_count += 1;
                    if seen.insert(name.to_string()) && a.imports.len() < MAX_LISTED {
                        a.imports.push(name.to_string());
                    }
                }
            }
        }
    }
    if lang.id == "go" {
        go_import_blocks(text, &mut a, &mut seen);
    }
    for (kind, re) in &c.symbols {
        for cap in re.captures_iter(text) {
            let Some(m) = cap.iter().skip(1).flatten().last() else { continue };
            let name = m.as_str().trim();
            // `augroup END` closes a Vim autocommand group.
            if is_keyword(name) || (*kind == "autocmd_group" && name == "END") {
                continue;
            }
            *a.symbol_counts.entry(kind).or_default() += 1;
            let list = a.symbols.entry(kind).or_default();
            if list.len() < MAX_LISTED && !list.iter().any(|x| x == name) {
                list.push(name.to_string());
            }
        }
    }
    a.package = c.package.as_ref().and_then(|re| re.captures(text)).map(|cap| cap[1].to_string());
    a
}

/// Words that the C-like function patterns would otherwise mistake for names.
fn is_keyword(w: &str) -> bool {
    matches!(w, "if" | "for" | "while" | "switch" | "return" | "sizeof" | "else" | "do" | "catch")
}

/// `import ( "fmt" ; alias "x/y" )` blocks.
fn go_import_blocks(text: &str, a: &mut Analysis, seen: &mut std::collections::HashSet<String>) {
    let mut inside = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("import (") {
            inside = true;
        } else if inside && t.starts_with(')') {
            inside = false;
        } else if inside && let Some(path) = t.split('"').nth(1) {
            a.import_count += 1;
            if seen.insert(path.to_string()) && a.imports.len() < MAX_LISTED {
                a.imports.push(path.to_string());
            }
        }
    }
}

/// Whether a line holds code and/or comment, tracking open block comments.
fn classify<'l>(line: &str, lang: &'l Lang, in_block: &mut Option<&'l str>, comments: &mut String) -> (bool, bool) {
    let (mut code, mut comment) = (false, false);
    let mut rest = line;
    let mut at_start = true;
    // Fixed-form COBOL: `*` or `/` in column 7 makes the line a comment.
    if lang.id == "cobol" && in_block.is_none() && matches!(line.as_bytes().get(6), Some(b'*' | b'/')) {
        if line.len() > 7 && comments.len() < MAX_COMMENT_TEXT {
            comments.push_str(&line[7..]);
            comments.push('\n');
        }
        return (false, true);
    }
    let keep = |s: &str, comments: &mut String| {
        if comments.len() < MAX_COMMENT_TEXT {
            comments.push_str(s);
            comments.push('\n');
        }
    };
    loop {
        if let Some(end) = *in_block {
            comment = true;
            if let Some(i) = rest.find(end) {
                keep(&rest[..i], comments);
                rest = &rest[i + end.len()..];
                *in_block = None;
            } else {
                keep(rest, comments);
                return (code, comment);
            }
        }
        rest = rest.trim_start();
        if rest.is_empty() {
            return (code, comment);
        }
        if let Some((open, close)) = lang.block.iter().find(|(o, _)| rest.starts_with(o)) {
            // `=begin`, `=pod` only open a block at the start of a line.
            if !open.starts_with('=') || at_start {
                *in_block = Some(close);
                rest = &rest[open.len()..];
                at_start = false;
                continue;
            }
        }
        if let Some(marker) = lang.line.iter().find(|m| {
            rest.starts_with(**m)
                && (!m.starts_with(|c: char| c.is_ascii_alphabetic() || matches!(c, '@' | '"' | '*')) || at_start)
                && (!m.ends_with(|c: char| c.is_ascii_alphabetic())
                    || !rest[m.len()..].starts_with(|c: char| c.is_alphanumeric()))
        }) {
            comment = true;
            keep(&rest[marker.len()..], comments);
            return (code, comment);
        }
        code = true;
        at_start = false;
        let first = rest.as_bytes()[0];
        if lang.quotes.contains(&first) {
            rest = skip_string(&rest[1..], first);
        } else {
            let n = rest.chars().next().map_or(1, char::len_utf8);
            rest = &rest[n..];
        }
    }
}

/// The rest of the line after a string closed by `q` (the whole line if it does not close).
fn skip_string(s: &str, q: u8) -> &str {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            i += 2;
        } else if b[i] == q {
            return &s[i + 1..];
        } else {
            i += 1;
        }
    }
    ""
}

/// Comment text without `//!`, `///`, `#`, `*` and similar markers.
fn strip_markers(s: &str) -> &str {
    let s = s.trim();
    let s = s
        .trim_start_matches(['/', '#', '*', ';', '%', '!', '-', '\''])
        .trim_start_matches("REM")
        .trim_start_matches("rem");
    let s = s.trim_end_matches("*/").trim_end_matches("-->").trim_end_matches("*)").trim_end_matches("-}");
    let s = s.trim_start_matches("/*").trim_start_matches("<!--").trim_start_matches("(*").trim_start_matches("{-");
    s.trim_start_matches(['*', '!']).trim()
}

fn looks_like_test(name: &str, text: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let by_name = n.starts_with("test_")
        || n.contains("_test.")
        || n.contains(".test.")
        || n.contains(".spec.")
        || n.contains("_spec.")
        || n.ends_with("test.java")
        || n.ends_with("tests.cs")
        || n.ends_with("test.kt");
    let head = &text[..text.char_indices().nth(64 * 1024).map_or(text.len(), |(i, _)| i)];
    by_name
        || [
            "#[test]",
            "#[cfg(test)]",
            "import pytest",
            "import unittest",
            "@Test",
            "[Fact]",
            "[TestMethod]",
            "RSpec.describe",
            "func Test",
        ]
        .iter()
        .any(|m| head.contains(m))
        || (head.contains("describe(") && head.contains("it("))
}

fn report(a: &Analysis, text: &str, lang: &Lang, cx: &mut Context<'_>) {
    let head = &text[..text.char_indices().nth(4096).map_or(text.len(), |(i, _)| i)];
    let generated =
        ["@generated", "DO NOT EDIT", "Code generated", "auto-generated", "autogenerated", "automatically generated"]
            .iter()
            .any(|m| head.contains(m));
    let lines = a.code + a.comment + a.blank;
    let minified = matches!(lang.id, "javascript" | "typescript" | "css")
        && text.len() > 2048
        && (a.longest_line > 5000 || (lines > 0 && text.len() as u64 / lines > 300));

    // Licence: an SPDX tag wins over a licence text in the header comment.
    if let Some(spdx) = spdx_identifier(text) {
        cx.rights().source("spdx").license(Some(&spdx), None);
        cx.format_set("spdx", spdx);
    } else if let Some(id) = identify_license(&a.header) {
        cx.rights().source("header_comment").license(Some(id), None);
        cx.format_set("license_header", id);
    }
    if let Some(c) = find_copyright(&a.header).or_else(|| find_copyright(head)) {
        cx.rights().copyright(c);
    }

    let doc = module_doc(text, lang, a);
    if let Some(d) = &doc {
        cx.emit_text(TextRole::Body, d);
        let first = d.split("\n\n").next().unwrap_or(d);
        cx.content().source("module_doc").description(truncate_chars(&crate::plugin::squash_whitespace(first), 300));
    }
    if !a.comments.is_empty() {
        cx.emit_text(TextRole::Comment, &a.comments);
    }
    let todos = todo_counts(&a.comments);

    let mut f = Map::new();
    let name = FORMATS.iter().find(|s| s.id == lang.id).map_or(lang.id, |s| s.name);
    f.insert("language".into(), json!(name.trim_end_matches(" source")));
    f.insert("loc".into(), json!({ "code": a.code, "comment": a.comment, "blank": a.blank, "total": lines }));
    if let Some(i) = shebang(head) {
        f.insert("interpreter".into(), json!(i));
    }
    if let Some(p) = &a.package {
        f.insert("package".into(), json!(p));
    }
    if !a.imports.is_empty() {
        f.insert("imports".into(), json!(a.imports));
        f.insert("import_count".into(), json!(a.import_count));
    }
    if !a.symbols.is_empty() {
        f.insert("symbols".into(), json!(a.symbols));
        f.insert("symbol_counts".into(), json!(a.symbol_counts));
    }
    if let Some(d) = doc {
        f.insert("module_doc".into(), json!(truncate_chars(&d, 500)));
    }
    if !todos.is_empty() {
        f.insert("todo_markers".into(), json!(todos));
    }
    f.insert("is_test".into(), json!(a.has_tests));
    f.insert("generated".into(), json!(generated));
    if matches!(lang.id, "javascript" | "typescript" | "css") {
        f.insert("minified".into(), json!(minified));
        if text.contains("sourceMappingURL=") {
            f.insert("source_map".into(), json!(true));
        }
    }
    f.insert("longest_line".into(), json!(a.longest_line));
    let fmt = cx.format();
    for (k, v) in f {
        fmt.insert(k, v);
    }
}

/// Module documentation: Rust `//!`, a Python module docstring, the comment
/// before Go's `package`, a leading `/** */`, or a header comment that is not
/// a licence notice.
fn module_doc(text: &str, lang: &Lang, a: &Analysis) -> Option<String> {
    let doc = match lang.id {
        "rust" => {
            let lines: Vec<&str> = text
                .lines()
                .skip_while(|l| l.trim().is_empty() || l.starts_with("#!["))
                .take_while(|l| l.trim_start().starts_with("//!") || l.trim().is_empty())
                .map(|l| {
                    l.trim_start()
                        .trim_start_matches("//!")
                        .strip_prefix(' ')
                        .unwrap_or(l.trim_start().trim_start_matches("//!"))
                })
                .collect();
            lines.join("\n")
        }
        "python" => {
            let body =
                text.lines().skip_while(|l| l.starts_with('#') || l.trim().is_empty()).collect::<Vec<_>>().join("\n");
            let q = if body.starts_with("\"\"\"") {
                "\"\"\""
            } else if body.starts_with("'''") {
                "'''"
            } else {
                ""
            };
            if q.is_empty() { String::new() } else { body[3..].split(q).next().unwrap_or("").to_string() }
        }
        "go" => {
            let mut block = Vec::new();
            for l in text.lines() {
                if l.starts_with("package ") {
                    break;
                }
                match l.strip_prefix("//") {
                    Some(c) => block.push(c.trim()),
                    None => block.clear(),
                }
            }
            block.join("\n")
        }
        _ => a.header.clone(),
    };
    let doc = doc.trim();
    let lower = doc.to_ascii_lowercase();
    let licence = lower.contains("copyright") || lower.contains("license") || lower.contains("spdx-");
    // A header that is only a licence notice is not documentation, except in
    // languages with a dedicated doc syntax (where it was picked deliberately).
    let documentation = !licence || matches!(lang.id, "rust" | "python" | "go");
    (!doc.is_empty() && documentation).then(|| truncate_chars(doc, 4000))
}

fn todo_counts(comments: &str) -> BTreeMap<&'static str, u64> {
    static TODO: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?-u:\b)(TODO|FIXME|HACK|XXX|BUG)(?-u:\b)").expect("valid"));
    let mut m = BTreeMap::new();
    for cap in TODO.captures_iter(comments) {
        let k = match &cap[1] {
            "TODO" => "TODO",
            "FIXME" => "FIXME",
            "HACK" => "HACK",
            "XXX" => "XXX",
            _ => "BUG",
        };
        *m.entry(k).or_default() += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lang(id: &str) -> &'static Lang {
        LANGS.iter().find(|l| l.id == id).unwrap()
    }

    #[test]
    fn line_classification() {
        let rust = lang("rust");
        let c = compiled(rust);
        let a = analyse(
            "//! Docs.\n\nuse std::io;\nfn main() { // hi\n  let s = \"/* not */\";\n}\n/* a\n b */\n",
            rust,
            &c,
        );
        assert_eq!((a.code, a.comment, a.blank), (4, 3, 1));
        assert_eq!(a.imports, ["std"]);
        assert_eq!(a.symbols["function"], ["main"]);
        let py = lang("python");
        let a =
            analyse("\"\"\"Module doc.\"\"\"\nimport os\nfrom a.b import c\n\ndef f():\n    pass\n", py, &compiled(py));
        assert_eq!(a.imports, ["os", "a.b"]);
        assert_eq!((a.code, a.comment, a.blank), (4, 1, 1));
        let bat = lang("batch");
        let mut open = None;
        let mut sink = String::new();
        assert_eq!(classify("REM comment", bat, &mut open, &mut sink), (false, true));
        assert_eq!(classify("echo REMARK", bat, &mut open, &mut sink), (true, false));
        assert_eq!(classify("REMOVE.exe", bat, &mut open, &mut sink), (true, false));
    }

    #[test]
    fn shared_extensions() {
        let pick = |ext: &str, text: &str| shared_extension(ext, text, text.as_bytes());
        assert_eq!(pick("v", "module counter (input clk);\nendmodule\n"), None);
        assert_eq!(pick("v", "Require Import Arith.\nLemma x : True.\n"), Some("coq"));
        assert_eq!(pick("v", "module main\n\nfn main() {\n}\n"), Some("vlang"));
        assert_eq!(pick("cl", "__kernel void k(__global float *a) {}\n"), Some("opencl"));
        assert_eq!(pick("cl", "(defun f (x) x)\n"), None);
        assert_eq!(pick("pp", "class harbour {\n  package { 'x': ensure => installed }\n}\n"), Some("puppet"));
        assert_eq!(pick("pp", "program Tides;\nbegin\nend.\n"), None);
        assert_eq!(pick("st", "PROGRAM MAIN\nVAR\n x : INT;\nEND_VAR\nEND_PROGRAM\n"), Some("plc_st"));
        assert_eq!(pick("cls", "\\NeedsTeXFormat{LaTeX2e}\n\\ProvidesClass{harbour}\n"), Some("latex"));
        assert_eq!(pick("cls", "VERSION 1.0 CLASS\nBEGIN\nEND\n"), Some("visual_basic"));
        assert_eq!(pick("cls", "public class Berths {}\n"), None);
        assert_eq!(pick("pls", "CREATE OR REPLACE PROCEDURE p IS BEGIN NULL; END;\n"), Some("plsql"));
        assert_eq!(pick("pls", "[playlist]\nFile1=a.mp3\n"), None);
        assert_eq!(shared_extension("res", "", b"RSRC\x00\x00"), None);
        assert_eq!(pick("res", "let x = 1\n"), Some("rescript"));
        assert_eq!(shared_extension("qs", "", b"\x00\x01binary"), None);
        assert_eq!(pick("qs", "namespace Tides {\n operation Go() : Unit {}\n}\n"), Some("qsharp"));
        assert_eq!(pick("vhd", "library ieee;\nentity e is end;\n"), Some("vhdl"));
    }

    #[test]
    fn detection_helpers() {
        assert_eq!(shebang("#!/usr/bin/env -S python3 -u\n").as_deref(), Some("python3"));
        assert_eq!(language_of_interpreter("python3.12"), Some("python"));
        assert_eq!(modeline("# -*- mode: ruby -*-\n"), Some("ruby"));
        assert_eq!(modeline("# vim: set ft=python:\n"), Some("python"));
        assert!(looks_like_test("test_api.py", ""));
        assert!(looks_like_test("lib.rs", "#[cfg(test)]\nmod tests {}"));
        assert_eq!(FORMATS.len(), LANGS.len());
    }

    crate::fixture_tests!(
        "c",
        "cpp",
        "cuda",
        "csharp",
        "java",
        "kotlin",
        "scala",
        "groovy",
        "go",
        "rust",
        "swift",
        "dart",
        "javascript",
        "typescript",
        "vue",
        "svelte",
        "css",
        "scss",
        "python",
        "ruby",
        "php",
        "perl",
        "shell",
        "powershell",
        "batch",
        "lua",
        "r",
        "julia",
        "haskell",
        "elixir",
        "erlang",
        "clojure",
        "ocaml",
        "fsharp",
        "zig",
        "objective_c",
        "matlab",
        "assembly",
        "graphql",
        "latex",
        "cmake",
        "nix",
        "visual_basic",
        "protobuf",
        "thrift",
        "capnp",
        "flatbuffers",
        "dhall",
        "jsonnet",
        "cuelang",
        "astro",
        "nim",
        "crystal",
        "d",
        "vlang",
        "odin",
        "fortran",
        "cobol",
        "pascal",
        "ada",
        "lisp",
        "scheme",
        "prolog",
        "elm",
        "purescript",
        "rescript",
        "coffeescript",
        "haxe",
        "tcl",
        "awk",
        "sed",
        "solidity",
        "move",
        "cairo",
        "vyper",
        "verilog",
        "vhdl",
        "opencl",
        "glsl",
        "hlsl",
        "wgsl",
        "metal",
        "apex",
        "abap",
        "smalltalk",
        "raku",
        "starlark",
        "meson",
        "ninja",
        "autohotkey",
        "autoit",
        "gleam",
        "roc",
        "unison",
        "mojo",
        "qsharp",
        "openqasm",
        "arduino",
        "llvm_ir",
        "wat",
        "antlr",
        "peg",
        "yacc",
        "lex",
        "puppet",
        "plsql",
        "go_template",
        "handlebars",
        "pug",
        "vim_script",
        "nushell",
        "elvish",
        "rego",
        "bicep",
        "lean",
        "coq",
        "agda",
        "idris",
        "isabelle",
        "tla",
        "alloy",
        "ballerina",
        "pony",
        "janet",
        "fennel",
        "hy",
        "forth",
        "apl",
        "j_lang",
        "gdscript",
        "shaderlab",
        "plc_st",
        "max_patch",
        "pure_data",
        "yara",
        "smithy",
        "avro_idl",
        "applescript"
    );
}
