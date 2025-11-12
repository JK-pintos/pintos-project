#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include <stdint.h>

typedef int fixed_t;
#define FP_SHIFT 14

#define FP_CONST(A) ((fixed_t)((A) << FP_SHIFT))
#define FP_TO_INT_ZERO(X) ((X) >> FP_SHIFT)                              
#define FP_TO_INT_ROUND(X) ((X) >= 0 ? ((X) + (1 << (FP_SHIFT - 1))) >> FP_SHIFT \
                                     : ((X) - (1 << (FP_SHIFT - 1))) >> FP_SHIFT)

#define FP_ADD(X,Y) ((X) + (Y))
#define FP_SUB(X,Y) ((X) - (Y))

#define FP_ADD_MIXED(X,N) ((X) + FP_CONST(N))
#define FP_SUB_MIXED(X,N) ((X) - FP_CONST(N))

#define FP_MUL(X,Y) ((fixed_t)(((int64_t)(X)) * (Y) >> FP_SHIFT))
#define FP_DIV(X,Y) ((fixed_t)(((int64_t)(X) << FP_SHIFT) / (Y)))

#define FP_MUL_MIXED(X,N) ((X) * (N))
#define FP_DIV_MIXED(X,N) ((X) / (N))

#endif /* threads/fixed-point.h */
