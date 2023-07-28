file(REMOVE_RECURSE
  "libiotivity-lite-client-python.pdb"
  "libiotivity-lite-client-python.so"
  "libiotivity-lite-client-python.so.2"
  "libiotivity-lite-client-python.so.2.2.5"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/client-python-shared.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
