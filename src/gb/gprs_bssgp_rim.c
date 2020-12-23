/*! \file gprs_bssgp.c
 * GPRS BSSGP RIM protocol implementation as per 3GPP TS 48.018. */
/*
 * (C) 2020 by sysmocom - s.f.m.c. GmbH
 * Author: Philipp Maier <pmaier@sysmocom.de>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <errno.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_bssgp_rim.h>

/* See also 3GPP TS 48.018 table 11.3.62a.1.b, table 11.3.62a.2.b, and table 11.3.62a.5.b. Those container
 * types share common IEs. */
#define DEC_RIM_CONT_COMMON \
	if (TLVP_PRESENT(&tp, BSSGP_IE_RIM_APP_IDENTITY)) \
		cont->app_id = TLVP_VAL(&tp, BSSGP_IE_RIM_APP_IDENTITY)[0]; \
	else \
		return -EINVAL; \
	if (TLVP_PRESENT(&tp, BSSGP_IE_RIM_SEQ_NR)) \
		cont->seq_num = tlvp_val32be(&tp, BSSGP_IE_RIM_SEQ_NR); \
	else \
		return -EINVAL; \
	if (TLVP_PRESENT(&tp, BSSGP_IE_RIM_PDU_INDICATIONS)) \
		memcpy(&cont->pdu_ind, TLVP_VAL(&tp, BSSGP_IE_RIM_PDU_INDICATIONS), sizeof(cont->pdu_ind)); \
	else \
		return -EINVAL; \
	if (TLVP_PRESENT(&tp, BSSGP_IE_RIM_PROTOCOL_VERSION)) \
		cont->prot_ver = TLVP_VAL(&tp, BSSGP_IE_RIM_PROTOCOL_VERSION)[0]; \
	else \
		cont->prot_ver = 1;

/* (requires max. 15 octets of memory, see also comment above) */
#define ENC_RIM_CONT_COMMON \
	uint32_t seq_num = osmo_htonl(cont->seq_num); \
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_APP_IDENTITY, 1, &cont->app_id); \
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_SEQ_NR, 4, (uint8_t*)&seq_num); \
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_PDU_INDICATIONS, sizeof(cont->pdu_ind), (uint8_t*)&cont->pdu_ind); \
	if (cont->prot_ver > 0) \
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_PROTOCOL_VERSION, 1, &cont->prot_ver); \

/*! Decode a RAN Information Request RIM Container (3GPP TS 48.018, table 11.3.62a.1.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_req_rim_cont(struct bssgp_ran_inf_req_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	DEC_RIM_CONT_COMMON if (TLVP_PRESENT(&tp, BSSGP_IE_RIM_REQ_APP_CONTAINER)) {
		cont->app_cont = TLVP_VAL(&tp, BSSGP_IE_RIM_REQ_APP_CONTAINER);
		cont->app_cont_len = TLVP_LEN(&tp, BSSGP_IE_RIM_REQ_APP_CONTAINER);
	} else {
		cont->app_cont = NULL;
		cont->app_cont_len = 0;
	}

	if (TLVP_PRESENT(&tp, BSSGP_IE_SON_TRANSFER_APP_ID)) {
		cont->son_trans_app_id = TLVP_VAL(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
		cont->son_trans_app_id_len = TLVP_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
	} else {
		cont->son_trans_app_id = NULL;
		cont->son_trans_app_id_len = 0;
	}

	return 0;
}

/*! Encode a RAN Information Request RIM Container (3GPP TS 48.018, table 11.3.62a.1.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_req_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_req_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;

	if (len < 15 + cont->app_cont_len + cont->son_trans_app_id_len)
		return -EINVAL;

	ENC_RIM_CONT_COMMON;

	if (cont->app_cont && cont->app_cont_len > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_REQ_APP_CONTAINER, cont->app_cont_len, cont->app_cont);

	if (cont->son_trans_app_id && cont->son_trans_app_id_len > 0)
		buf_ptr =
		    tvlv_put(buf_ptr, BSSGP_IE_SON_TRANSFER_APP_ID, cont->son_trans_app_id_len, cont->son_trans_app_id);

	return (int)(buf_ptr - buf);
}

/*! Decode a RAN Information RIM Container (3GPP TS 48.018, table 11.3.62a.2.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_rim_cont(struct bssgp_ran_inf_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	DEC_RIM_CONT_COMMON if (TLVP_PRESENT(&tp, BSSGP_IE_RAN_INFO_APP_CONTAINER)) {
		cont->app_cont = TLVP_VAL(&tp, BSSGP_IE_RAN_INFO_APP_CONTAINER);
		cont->app_cont_len = TLVP_LEN(&tp, BSSGP_IE_RAN_INFO_APP_CONTAINER);
	} else {
		cont->app_cont = NULL;
		cont->app_cont_len = 0;
	}

	if (TLVP_PRESENT(&tp, BSSGP_IE_APP_ERROR_CONTAINER)) {
		cont->app_err_cont = TLVP_VAL(&tp, BSSGP_IE_APP_ERROR_CONTAINER);
		cont->app_err_cont_len = TLVP_LEN(&tp, BSSGP_IE_APP_ERROR_CONTAINER);
		cont->app_cont = NULL;
		cont->app_cont_len = 0;
	} else {
		cont->app_err_cont = NULL;
		cont->app_err_cont_len = 0;
	}

	if (TLVP_PRESENT(&tp, BSSGP_IE_SON_TRANSFER_APP_ID)) {
		cont->son_trans_app_id = TLVP_VAL(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
		cont->son_trans_app_id_len = TLVP_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
	} else {
		cont->son_trans_app_id = NULL;
		cont->son_trans_app_id_len = 0;
	}

	return 0;
}

/*! Encode a RAN Information RIM Container (3GPP TS 48.018, table 11.3.62a.2.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;

	if (len < 15 + cont->app_err_cont_len + cont->app_cont_len + cont->son_trans_app_id_len)
		return -EINVAL;

	ENC_RIM_CONT_COMMON;

	if (cont->app_err_cont && cont->app_err_cont_len > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_REQ_APP_CONTAINER, cont->app_err_cont_len, cont->app_err_cont);
	else if (cont->app_cont && cont->app_cont_len > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_REQ_APP_CONTAINER, cont->app_cont_len, cont->app_cont);

	if (cont->son_trans_app_id && cont->son_trans_app_id_len > 0)
		buf_ptr =
		    tvlv_put(buf_ptr, BSSGP_IE_SON_TRANSFER_APP_ID, cont->son_trans_app_id_len, cont->son_trans_app_id);

	return (int)(buf_ptr - buf);
}

/*! Decode a RAN Information ACK RIM Container (3GPP TS 48.018, table 11.3.62a.3.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_ack_rim_cont(struct bssgp_ran_inf_ack_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	if (TLVP_PRESENT(&tp, BSSGP_IE_RIM_APP_IDENTITY))
		cont->app_id = TLVP_VAL(&tp, BSSGP_IE_RIM_APP_IDENTITY)[0];
	else
		return -EINVAL;

	if (TLVP_PRESENT(&tp, BSSGP_IE_RIM_SEQ_NR))
		cont->seq_num = tlvp_val32be(&tp, BSSGP_IE_RIM_SEQ_NR);
	else
		return -EINVAL;

	if (TLVP_PRESENT(&tp, BSSGP_IE_RIM_PROTOCOL_VERSION))
		cont->prot_ver = TLVP_VAL(&tp, BSSGP_IE_RIM_PROTOCOL_VERSION)[0];
	else
		cont->prot_ver = 1;

	if (TLVP_PRESENT(&tp, BSSGP_IE_SON_TRANSFER_APP_ID)) {
		cont->son_trans_app_id = TLVP_VAL(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
		cont->son_trans_app_id_len = TLVP_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
	} else {
		cont->son_trans_app_id = NULL;
		cont->son_trans_app_id_len = 0;
	}

	return 0;
}

/*! Encode a RAN Information ACK RIM Container (3GPP TS 48.018, table 11.3.62a.3.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_ack_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_ack_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;
	uint32_t seq_num = osmo_htonl(cont->seq_num);

	if (len < 13 + cont->son_trans_app_id_len)
		return -EINVAL;

	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_APP_IDENTITY, 1, &cont->app_id);
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_SEQ_NR, 4, (uint8_t *) & seq_num);

	if (cont->prot_ver > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_PROTOCOL_VERSION, 1, &cont->prot_ver);

	if (cont->son_trans_app_id && cont->son_trans_app_id_len > 0)
		buf_ptr =
		    tvlv_put(buf_ptr, BSSGP_IE_SON_TRANSFER_APP_ID, cont->son_trans_app_id_len, cont->son_trans_app_id);

	return (int)(buf_ptr - buf);
}

/*! Decode a RAN Information Error RIM Container (3GPP TS 48.018, table 11.3.62a.4.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_err_rim_cont(struct bssgp_ran_inf_err_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	if (TLVP_PRESENT(&tp, BSSGP_IE_RIM_APP_IDENTITY))
		cont->app_id = TLVP_VAL(&tp, BSSGP_IE_RIM_APP_IDENTITY)[0];
	else
		return -EINVAL;

	if (TLVP_PRESENT(&tp, BSSGP_IE_CAUSE))
		cont->cause = TLVP_VAL(&tp, BSSGP_IE_CAUSE)[0];
	else
		return -EINVAL;

	if (TLVP_PRESENT(&tp, BSSGP_IE_RIM_PROTOCOL_VERSION))
		cont->prot_ver = TLVP_VAL(&tp, BSSGP_IE_RIM_PROTOCOL_VERSION)[0];
	else
		cont->prot_ver = 1;

	if (TLVP_PRESENT(&tp, BSSGP_IE_PDU_IN_ERROR)) {
		cont->err_pdu = TLVP_VAL(&tp, BSSGP_IE_PDU_IN_ERROR);
		cont->err_pdu_len = TLVP_LEN(&tp, BSSGP_IE_PDU_IN_ERROR);
	} else
		return -EINVAL;

	if (TLVP_PRESENT(&tp, BSSGP_IE_SON_TRANSFER_APP_ID)) {
		cont->son_trans_app_id = TLVP_VAL(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
		cont->son_trans_app_id_len = TLVP_LEN(&tp, BSSGP_IE_SON_TRANSFER_APP_ID);
	} else {
		cont->son_trans_app_id = NULL;
		cont->son_trans_app_id_len = 0;
	}

	return 0;
}

/*! Encode a RAN Information Error RIM Container (3GPP TS 48.018, table 11.3.62a.4.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_err_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_err_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;

	if (len < 9 + cont->err_pdu_len + cont->son_trans_app_id_len)
		return -EINVAL;

	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_APP_IDENTITY, 1, &cont->app_id);
	buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_CAUSE, 1, &cont->cause);

	if (cont->prot_ver > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_RIM_PROTOCOL_VERSION, 1, &cont->prot_ver);

	if (cont->err_pdu && cont->err_pdu_len > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_PDU_IN_ERROR, cont->err_pdu_len, cont->err_pdu);
	else
		return -EINVAL;

	if (cont->son_trans_app_id && cont->son_trans_app_id_len > 0)
		buf_ptr =
		    tvlv_put(buf_ptr, BSSGP_IE_SON_TRANSFER_APP_ID, cont->son_trans_app_id_len, cont->son_trans_app_id);

	return (int)(buf_ptr - buf);
}

/*! Decode a RAN Information Application Error RIM Container (3GPP TS 48.018, table 11.3.62a.5.b).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_app_err_rim_cont(struct bssgp_ran_inf_app_err_rim_cont *cont, const uint8_t *buf, size_t len)
{
	int rc;
	struct tlv_parsed tp;

	memset(cont, 0, sizeof(*cont));

	rc = tlv_parse(&tp, &tvlv_att_def, buf, len, 0, 0);
	if (rc < 0)
		return -EINVAL;

	DEC_RIM_CONT_COMMON if (TLVP_PRESENT(&tp, BSSGP_IE_APP_ERROR_CONTAINER)) {
		cont->app_err_cont = TLVP_VAL(&tp, BSSGP_IE_APP_ERROR_CONTAINER);
		cont->app_err_cont_len = TLVP_LEN(&tp, BSSGP_IE_APP_ERROR_CONTAINER);
	} else
		return -EINVAL;

	return 0;
}

/*! Encode a RAN Information Application Error RIM Container (3GPP TS 48.018, table 11.3.62a.5.b).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_app_err_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_app_err_rim_cont *cont)
{
	uint8_t *buf_ptr = buf;

	if (len < 15 + cont->app_err_cont_len)
		return -EINVAL;

	ENC_RIM_CONT_COMMON;

	if (cont->app_err_cont && cont->app_err_cont_len > 0)
		buf_ptr = tvlv_put(buf_ptr, BSSGP_IE_APP_ERROR_CONTAINER, cont->app_err_cont_len, cont->app_err_cont);
	else
		return -EINVAL;

	return (int)(buf_ptr - buf);

	return 0;
}

/*! Decode a RAN Information Request Application Container for NACC (3GPP TS 48.018, section 11.3.63.1.1).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_req_app_cont_nacc(struct bssgp_ran_inf_req_app_cont_nacc *cont, const uint8_t *buf, size_t len)
{
	if (len < 8)
		return -EINVAL;
	cont->reprt_cell.cid = bssgp_parse_cell_id(&cont->reprt_cell.raid, buf);
	return 0;
}

/*! Encode a RAN Information Request Application Container for NACC (3GPP TS 48.018, section 11.3.63.1.1).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_req_app_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_ran_inf_req_app_cont_nacc *cont)
{
	int rc;

	if (len < 10)
		return -EINVAL;

	rc = bssgp_create_cell_id(buf, &cont->reprt_cell.raid, cont->reprt_cell.cid);
	if (rc < 0)
		return -EINVAL;
	return rc;
}

/*! Decode a RAN Information Application Container (3GPP TS 48.018, section 11.3.63.2.1).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_ran_inf_app_cont_nacc(struct bssgp_ran_inf_app_cont_nacc *cont, const uint8_t *buf, size_t len)
{
	unsigned int i;

	if (len < 9)
		return -EINVAL;

	cont->reprt_cell.cid = bssgp_parse_cell_id(&cont->reprt_cell.raid, buf);

	buf += 8;

	cont->type_psi = buf[0] & 1;
	cont->num_si = buf[0] >> 1;

	if (cont->type_psi && (len - 8) / 22 != cont->num_si)
		return -EINVAL;
	else if ((len - 8) / 21 != cont->num_si)
		return -EINVAL;

	buf++;

	for (i = 0; i < cont->num_si; i++) {
		cont->si[i] = buf;
		if (cont->type_psi)
			buf += 22;
		else
			buf += 21;
	}

	return 0;
}

/*! Encode a RAN Information Application Container (3GPP TS 48.018, section 11.3.63.2.1).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_ran_inf_app_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_ran_inf_app_cont_nacc *cont)
{
	uint8_t *buf_ptr = buf;
	int rc;
	unsigned int silen;
	unsigned int i;

	if (cont->type_psi)
		silen = 22;
	else
		silen = 21;

	if (len < 11 + silen * cont->num_si)
		return -EINVAL;

	rc = bssgp_create_cell_id(buf_ptr, &cont->reprt_cell.raid, cont->reprt_cell.cid);
	if (rc < 0)
		return -EINVAL;
	buf_ptr += rc;

	buf_ptr[0] = 0x00;
	if (cont->type_psi)
		buf_ptr[0] |= 0x01;
	buf_ptr[0] |= (cont->num_si << 1);
	buf_ptr++;

	for (i = 0; i < cont->num_si; i++) {
		memcpy(buf_ptr, cont->si[i], silen);
		buf_ptr += silen;
	}

	return (int)(buf_ptr - buf);
}

/*! Decode a Application Error Container for NACC (3GPP TS 48.018, section 11.3.64.1).
 *  \param[out] user provided memory for decoded data struct.
 *  \param[in] buf user provided memory with the encoded value data of the IE.
 *  \returns 0 on success, -EINVAL on error. */
int bssgp_dec_app_err_cont_nacc(struct bssgp_app_err_cont_nacc *cont, const uint8_t *buf, size_t len)
{
	if (len < 1)
		return -EINVAL;

	cont->nacc_cause = buf[0];
	buf++;
	cont->err_app_cont = buf;
	cont->err_app_cont_len = len - 1;

	return 0;
}

/*! Encode Application Error Container for NACC (3GPP TS 48.018, section 11.3.64.1).
 *  \param[out] buf user provided memory for the generated value part of the IE.
 *  \param[in] cont user provided input data struct.
 *  \returns length of encoded octets, -EINVAL on error. */
int bssgp_enc_app_err_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_app_err_cont_nacc *cont)
{
	uint8_t *buf_ptr = buf;

	buf_ptr[0] = cont->nacc_cause;
	buf_ptr++;

	memcpy(buf_ptr, cont->err_app_cont, cont->err_app_cont_len);
	buf_ptr += cont->err_app_cont_len;

	return (int)(buf_ptr - buf);
}
