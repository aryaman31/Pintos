#include <float.h>

/* Type conversion. */
fixed_point int_to_fixed_point(int n);
int fixed_point_to_int(fixed_point x);
int fixed_point_to_zero_int(fixed_point x);

/* Fixed point only arithmetic operations. */
fixed_point add_f(fixed_point x, fixed_point y);
fixed_point sub_f(fixed_point x, fixed_point y);
fixed_point mul_f(fixed_point x, fixed_point y);
fixed_point div_f(fixed_point x, fixed_point y);

/* Fixed point and integer arithmetic operations. */
fixed_point add_i(fixed_point x, int n);
fixed_point sub_i(fixed_point x, int n);
fixed_point mul_i(fixed_point x, int n);
fixed_point div_i(fixed_point x, int n);

/* Converts an integer to a fixed point value. */
fixed_point int_to_fixed_point(int n) {
  return (fixed_point) n * F;
}

/* Functions implemented according to table in section B.6. */ 
/* Converts a fixed point value to an integer rounded towards zero*/ 
int fixed_point_to_zero_int(fixed_point x) {
  return (int) x / F;
}

/* Converts a fixed point value to an integer*/ 
int fixed_point_to_int(fixed_point x) {
  if (x >= 0) {
    return (int) (x + (F / 2)) / F;
  } else {
    return (int) (x - (F / 2)) / F;
  }
}

/* Add two fixed point integers. */
fixed_point add_f(fixed_point x, fixed_point y) {
  return (fixed_point) x + y;
}

/* Subtract two fixed point integers. */
fixed_point sub_f(fixed_point x, fixed_point y) {
  return (fixed_point) x - y;
}

/* Multiply two fixed point integers. */
fixed_point mul_f(fixed_point x, fixed_point y) {
  return (fixed_point) ((int64_t) x) * y / F;
}

/* Divide two fixed point integers. */
fixed_point div_f(fixed_point x, fixed_point y) {
  return (fixed_point) ((int64_t) x) * F / y;
}

/* Add a fixed point and an integer. */
fixed_point add_i(fixed_point x, int n) {
  return (fixed_point) x + (n * F);
}
/* Subtract an integer from a fixed point. */
fixed_point sub_i(fixed_point x, int n) {
  return (fixed_point) x - (n * F);
}

/* Multiply a fixed point and an integer. */
fixed_point mul_i(fixed_point x, int n) {
  return (fixed_point) x * n;
}

/* Divide a fixed point by an integer. */
fixed_point div_i(fixed_point x, int n) {
  return (fixed_point) x / n;
}
