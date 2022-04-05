#ifndef __FLOAT_H
#define FLOAT_H
#include <stdint.h>

/* Defines a number in 17.14 fixed-point format, i.e. 
17 bits before decimal point and 14 bits after. */

/* F = 2 ^ q, where q = 14. */
#define F (1 << 14)

/* Typedef to represent floating point number.*/
typedef signed long long int fixed_point;

/* Type conversion.*/
fixed_point int_to_fixed_point(int);
int fixed_point_to_int(fixed_point);
int fixed_point_to_zero_int(fixed_point);

/* Fixed point only arithmetic operations.*/
fixed_point add_f(fixed_point, fixed_point);
fixed_point sub_f(fixed_point, fixed_point);
fixed_point mul_f(fixed_point, fixed_point);
fixed_point div_f(fixed_point, fixed_point);

/* Fixed point and integer arithmetic operations. */
fixed_point add_i(fixed_point, int);
fixed_point sub_i(fixed_point, int);
fixed_point mul_i(fixed_point, int);
fixed_point div_i(fixed_point, int);

#endif
