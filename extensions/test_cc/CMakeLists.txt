# The test_cc extension
PROJECT("Credit Control dummy server" C)

FD_ADD_EXTENSION(test_cc test_cc.c)

TARGET_LINK_LIBRARIES(test_cc -lnats -L/usr/local/lib64})

####
## INSTALL section ##

INSTALL(TARGETS test_cc
	LIBRARY DESTINATION ${INSTALL_EXTENSIONS_SUFFIX}
	COMPONENT freeDiameter-debug-tools)

