# tree-sitter-swift 0.5.0

The Swift grammar used by datawarden's Swift frontend. These are the generated sources (`parser.c`, `scanner.c` and `tree_sitter/*.h`) of [alex-pinkus/tree-sitter-swift](https://github.com/alex-pinkus/tree-sitter-swift), tag `0.5.0-with-generated-files` (commit `57c1c6d6ffa1c44b330182d41717e6fe37430704`), unmodified. They are licensed under the MIT license in [LICENSE](LICENSE). `binding.go` is datawarden's.

**Why the grammar is vendored:**

- The 0.5.0 tag has no Go bindings.
- Every newer release parses real Swift code worse, even after `swiftNormalize`. On 147 Swift files from real projects, the number that fail to parse is:

  | Release | Files that fail |
  |---|---|
  | 0.5.0 | 4 |
  | 0.7.1 and 0.7.2 | 7 |
  | 0.7.3 | 8 |

- It is the same grammar as the one bundled with `smacker/go-tree-sitter`, which datawarden used before. The files are byte-identical, so it produces the same trees.

**To update:**

1. Copy `src/parser.c`, `src/scanner.c` and `src/tree_sitter/` from a `*-with-generated-files` tag into this directory.
2. Update the tag and commit above.
3. Check the grammar's ABI version: `LANGUAGE_VERSION` in `parser.c` must be 13 to 15, the versions `github.com/tree-sitter/go-tree-sitter` loads.
4. Run the tests, which include `TestConformanceProgramsParseCleanly` and `TestSwiftNewerSyntaxParses`.
5. Compare parse failures on real code, as in [#44](https://github.com/GoNetTools/datawarden/issues/44).
