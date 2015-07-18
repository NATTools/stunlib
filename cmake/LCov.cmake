# TODO: parameterize for reuse
add_custom_target(coverage_report
  COMMAND lcov --directory src/CMakeFiles/spud.dir --capture --output-file spudlib.info
  COMMAND genhtml --output-directory lcov spudlib.info
  COMMAND echo "Coverage report in: file://${CMAKE_BINARY_DIR}/lcov/index.html"
)
