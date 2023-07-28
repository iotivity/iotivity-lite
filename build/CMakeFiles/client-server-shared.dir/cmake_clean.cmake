file(REMOVE_RECURSE
  "libiotivity-lite-client-server.pdb"
  "libiotivity-lite-client-server.so"
  "libiotivity-lite-client-server.so.2"
  "libiotivity-lite-client-server.so.2.2.5"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/client-server-shared.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
