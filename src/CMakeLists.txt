#
#
# compiling/installing sources for stunlib

set ( stunlib_srcs
      stunclient.c
      stunserver.c
      stunlib.c
      turnclient.c
      stuntrace.c
      stun_random.c
      stun_crc32.c
      stun_md5.c
      stun_sha1.c
)

set (ADDITIONAL_LIBS "")

add_library ( stunlib SHARED ${stunlib_srcs} )
target_include_directories ( stunlib PUBLIC ../include )
target_include_directories ( stunlib PRIVATE ../src )


install ( TARGETS stunlib
          LIBRARY DESTINATION lib
          ARCHIVE DESTINATION lib
          RUNTIME DESTINATION bin)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)

target_link_libraries ( stunlib PRIVATE sockaddrutil
                        ${ADDITIONAL_LIBS})

if (coveralls)
    include(Coveralls)
    coveralls_turn_on_coverage()

    set(COVERAGE_SRCS "")
    foreach (S ${stunlib_srcs})
      get_filename_component(S_ABS ${S} ABSOLUTE)
      list (APPEND COVERAGE_SRCS ${S_ABS})
    endforeach()

    # Create the coveralls target.
    coveralls_setup(
        "${COVERAGE_SRCS}"
        ${coveralls_send}                 # If we should upload.
    )

    #add_dependencies(coveralls, all)
endif()
