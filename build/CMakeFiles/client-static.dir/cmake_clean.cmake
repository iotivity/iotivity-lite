file(REMOVE_RECURSE
  "libiotivity-lite-client-static.a"
  "libiotivity-lite-client-static.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/client-static.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
