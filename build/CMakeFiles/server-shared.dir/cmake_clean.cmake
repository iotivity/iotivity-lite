file(REMOVE_RECURSE
  "libiotivity-lite-server.pdb"
  "libiotivity-lite-server.so"
  "libiotivity-lite-server.so.2"
  "libiotivity-lite-server.so.2.2.5"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/server-shared.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
