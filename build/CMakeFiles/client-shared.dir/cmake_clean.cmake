file(REMOVE_RECURSE
  "libiotivity-lite-client.pdb"
  "libiotivity-lite-client.so"
  "libiotivity-lite-client.so.2"
  "libiotivity-lite-client.so.2.2.5"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/client-shared.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
