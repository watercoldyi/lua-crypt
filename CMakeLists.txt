cmake_minimum_required(VERSION 3.15)
project(lua_crypt C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 默认链接 LuaJIT；-DUSE_LUAJIT=OFF 则使用 PUC Lua（由 find_package(Lua) 查找）
option(USE_LUAJIT "使用 LuaJIT 而非 PUC Lua" ON)

add_library(crypt MODULE
  lsha1.c
  lsha256.c
  md5.c
  lmd5.c
  aes128.c
  aes256.c
  laes.c
  lua-crypt.c
  md5.h
  aes.h
  aes_variants.h)

if(USE_LUAJIT)
  find_package(PkgConfig QUIET)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(LUA QUIET IMPORTED_TARGET luajit)
  endif()

  if(TARGET PkgConfig::LUA)
    target_link_libraries(crypt PRIVATE PkgConfig::LUA)
  else()
    # 没有 pkg-config 时退化为手动查找
    find_path(LUAJIT_INCLUDE_DIR NAMES lua.h PATH_SUFFIXES luajit-2.1)
    find_library(LUAJIT_LIBRARY NAMES luajit-5.1 luajit)
    if(NOT LUAJIT_INCLUDE_DIR OR NOT LUAJIT_LIBRARY)
      message(FATAL_ERROR "找不到 LuaJIT；请安装 luajit 和 pkg-config，或使用 -DUSE_LUAJIT=OFF 构建 PUC Lua 版本")
    endif()
    target_include_directories(crypt PRIVATE ${LUAJIT_INCLUDE_DIR})
    target_link_libraries(crypt PRIVATE ${LUAJIT_LIBRARY})
  endif()
else()
  find_package(Lua REQUIRED)
  target_include_directories(crypt PRIVATE ${LUA_INCLUDE_DIR})
  target_link_libraries(crypt PRIVATE ${LUA_LIBRARIES})
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(crypt PRIVATE -Wall)
endif()

# Windows 下 BCryptGenRandom 需要链接 bcrypt
if(WIN32)
  target_link_libraries(crypt PRIVATE bcrypt)
endif()

# Lua 模块必须命名为 crypt.so；macOS 默认会给模块加 lib 前缀
set_target_properties(crypt PROPERTIES PREFIX "")
