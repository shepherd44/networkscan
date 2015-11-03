#include <iostream>

#include "gtest/gtest.h"

int main(int argc, char *argv[])
{
	argc = 2;
	char *argvtemp[2];
	argvtemp[0] = argv[0];
	argvtemp[1] = "";

	std::cout << "";

	testing::InitGoogleTest(&argc, argvtemp);

	return RUN_ALL_TESTS();
}