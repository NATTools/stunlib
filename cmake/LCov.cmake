# TODO: parameterize for reuse
add_custom_target(coverage_report
  COMMAND lcov --directory src/CMakeFiles/stunlib.dir --capture --output-file stunlib.info
  COMMAND genhtml --output-directory lcov stunlib.info
  COMMAND echo "Coverage report in: file://${CMAKE_BINARY_DIR}/lcov/index.html"
)
