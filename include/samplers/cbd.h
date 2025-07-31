/// Last modified at 2025年07月16日 星期三 10时52分25秒

/// 中心二项分布采样函数
#include "../aigis_const.h"

#ifndef __CBD_H__
#define __CBD_H__

static void cbd1(int16_t *res, const uint8_t *ref_buf);
static void cbd2(int16_t *res, const uint8_t *ref_buf);
static void cbd3(int16_t *res, const uint8_t *ref_buf);
static void cbd4(int16_t *res, const uint8_t *ref_buf);
static void cbd8(int16_t *res, const uint8_t *ref_buf);
int cbd_eta(
	uint8_t scale, int16_t *res,
	const uint8_t *buf
);
#endif // CBD_H
