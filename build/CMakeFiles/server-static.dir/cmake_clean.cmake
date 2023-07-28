file(REMOVE_RECURSE
  "libiotivity-lite-server-static.a"
  "libiotivity-lite-server-static.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/server-static.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
