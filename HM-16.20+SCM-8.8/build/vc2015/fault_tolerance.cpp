#include "fault_tolerance.h"
int error_count;
void erro_start()
{
	error_count = 0;
}
void erro_add()
{
	error_count++;
}
int erro_get()
{
	return error_count;
}
