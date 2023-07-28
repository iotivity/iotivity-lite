file(REMOVE_RECURSE
  "libiotivity-lite-client-server-static.a"
  "libiotivity-lite-client-server-static.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/client-server-static.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
