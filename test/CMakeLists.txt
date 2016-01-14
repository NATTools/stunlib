#
#
# Compiling/running tests


set ( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${dist_dir}/test )

function (sa_test name)
  add_executable ( ${name}_test ${name}_test.c test_utils.c)
  target_link_libraries ( ${name}_test PRIVATE stunlib sockaddrutil )
  target_include_directories ( ${name}_test PRIVATE ../include )
  add_test ( NAME ${name} COMMAND ${name}_test )
endfunction()

sa_test ( testvector )
sa_test ( realworldpackets )
sa_test ( stunclient )
sa_test ( turnmessage )
sa_test ( stunserver )
sa_test ( turnclient )



include ( CTest )
