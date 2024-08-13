if(NOT (LIBCONFIG_INCLUDE_DIR AND LIBCONFIG_LIBRARY))
  find_package(PkgConfig)
  pkg_check_modules(PC_LIBCONFIG QUIET libconfig)

  find_path(LIBCONFIG_INCLUDE_DIR
    NAMES
      libconfig.h
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(LIBCONFIG_LIBRARY
    NAMES
	  config
      libconfig
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  mark_as_advanced(LIBCONFIG_INCLUDE_DIR LIBCONFIG_LIBRARY)
endif(NOT (LIBCONFIG_INCLUDE_DIR AND LIBCONFIG_LIBRARY))

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LIBCONFIG
    FOUND_VAR LIBCONFIG_FOUND
    REQUIRED_VARS LIBCONFIG_LIBRARY LIBCONFIG_INCLUDE_DIR)

if(LIBCONFIG_FOUND)
  set(LIBCONFIG_LIBRARIES ${LIBCONFIG_LIBRARY})
  set(LIBCONFIG_INCLUDE_DIRS ${LIBCONFIG_INCLUDE_DIR})
  set(LIBCONFIG_DEFINITIONS ${PC_LIBCONFIG_CFLAGS_OTHER})
endif()

if(LIBCONFIG_FOUND AND NOT TARGET LIBCONFIG::LIBCONFIG)
  add_library(LIBCONFIG::LIBCONFIG UNKNOWN IMPORTED)
  set_target_properties(
      LIBCONFIG::LIBCONFIG PROPERTIES
      IMPORTED_LOCATION "${LIBCONFIG_LIBRARY}"
      INTERFACE_COMPILE_OPTIONS "${PC_LIBCONFIG_CFLAGS_OTHER}"
      INTERFACE_INCLUDE_DIRECTORIES "${LIBCONFIG_INCLUDE_DIR}")
endif()

