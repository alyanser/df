cmake_minimum_required(VERSION 3.20)

project(dh)

add_executable(${PROJECT_NAME}
	dh.c
)

target_link_libraries(${PROJECT_NAME}
	ssl
	crypto
)
