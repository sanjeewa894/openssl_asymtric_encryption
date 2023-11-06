cmake_minimum_required(VERSION 3.14)

project(openssl_asymetric LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

add_executable(openssl_asymetric
  main.cpp
  asymetric_encryption.cpp asymetric_encryption.h
)
target_link_libraries(openssl_asymetric Qt${QT_VERSION_MAJOR}::Core)

include(GNUInstallDirs)
install(TARGETS openssl_asymetric
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
find_package(OpenSSL REQUIRED)
target_link_libraries(${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)
