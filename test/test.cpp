
#include <iostream>
#include <typeinfo.h>


#include "../mylist/linkedlist.h"

using namespace std;


#define typeof(type)	sizeof(type)

struct entry
{
	int a;
	char c;
	int b;
	char cc[4];
	ListHead list;
};

int main(int argc, char *argv[])
{
}