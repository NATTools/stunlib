find_program(UNCRUSTIFY_EXE uncrustify)
if (DEFINED UNCRUSTIFY_EXE)
  set (UNCRUSTIFY_FOUND ON)
  set (uncrustify_cfg "${PROJECT_SOURCE_DIR}/uncrustify.cfg")
else()
  set (UNCRUSTIFY_FOUND OFF)
endif()

function(UncrustifyTop enabled)
  if (NOT enabled)
    return()
  endif()

  if (NOT UNCRUSTIFY_FOUND)
    message(FATAL_ERROR "Uncrustify is needed to pretty up the source.")
  endif()

  add_custom_target(uncrustify
      COMMENT "Prettying source code with uncrustify")
endfunction()

function(UncrustifyDir file_list_var)
  get_filename_component(THIS_DIR "${CMAKE_CURRENT_SOURCE_DIR}" NAME)
  set(THIS_TS "${CMAKE_CURRENT_SOURCE_DIR}/.uncrustify_time")

  add_custom_command(
    OUTPUT "${THIS_TS}"
    COMMAND "${UNCRUSTIFY_EXE}" --replace --no-backup -c "${uncrustify_cfg}" ${${file_list_var}}
    COMMAND touch "${THIS_TS}"
    DEPENDS ${${file_list_var}} "${uncrustify_cfg}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Uncrustifying ${THIS_DIR}")
  add_custom_target(
    "uncrustify-${THIS_DIR}"
    DEPENDS "${THIS_TS}")
  add_dependencies(uncrustify "uncrustify-${THIS_DIR}")
endfunction()
