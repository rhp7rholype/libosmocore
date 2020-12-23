#pragma once

#include <osmocom/gprs/protocol/gsm_08_18.h>

enum bssgp_rim_routing_info_discr {
	BSSGP_RIM_ROUTING_INFO_GERAN,
	BSSGP_RIM_ROUTING_INFO_UTRAN,
	BSSGP_RIM_ROUTING_INFO_EUTRAN,
};

/*! BSSGP RIM Routing information, see also 3GPP TS 48.018, section 11.3.70 */
struct bssgp_rim_routing_info {
	enum bssgp_rim_routing_info_discr discr;
	union {
		struct {
			struct gprs_ra_id raid;
			uint16_t cid;
		} geran;
		struct {
			struct gprs_ra_id raid;
			uint16_t rncid;
		} utran;
		struct {
			struct osmo_eutran_tai tai;
			/* See also 3GPP TS 36.413 9.2.1.37 and 3GPP TS 36.401 */
			uint8_t global_enb_id[8];
			uint8_t global_enb_id_len;
		} eutran;
	};
};

int bssgp_parse_rim_ri(struct bssgp_rim_routing_info *ri, const uint8_t *buf, unsigned int len);
int bssgp_create_rim_ri(uint8_t *buf, const struct bssgp_rim_routing_info *ri);

/* 3GPP TS 48.018, table 11.3.62a.1.b: RAN-INFORMATION-REQUEST RIM Container Contents */
struct bssgp_ran_inf_req_rim_cont {
	uint8_t app_id;
	uint32_t seq_num;
	struct bssgp_rim_pdu_ind pdu_ind;
	uint8_t prot_ver;

	/* Pointer to nested containers */
	const uint8_t *app_cont;
	size_t app_cont_len;
	const uint8_t *son_trans_app_id;
	size_t son_trans_app_id_len;
};

int bssgp_dec_ran_inf_req_rim_cont(struct bssgp_ran_inf_req_rim_cont *cont, const uint8_t *buf, size_t len);
int bssgp_enc_ran_inf_req_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_req_rim_cont *cont);

/* 3GPP TS 48.018, table 11.3.62a.2.b: RAN-INFORMATION RIM Container Contents */
struct bssgp_ran_inf_rim_cont {
	uint8_t app_id;
	uint32_t seq_num;
	struct bssgp_rim_pdu_ind pdu_ind;
	uint8_t prot_ver;

	/* Pointer to nested containers */
	const uint8_t *app_cont;
	size_t app_cont_len;
	const uint8_t *app_err_cont;
	size_t app_err_cont_len;
	const uint8_t *son_trans_app_id;
	size_t son_trans_app_id_len;
};

int bssgp_dec_ran_inf_rim_cont(struct bssgp_ran_inf_rim_cont *cont, const uint8_t *buf, size_t len);
int bssgp_enc_ran_inf_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_rim_cont *cont);

/* 3GPP TS 48.018, table 11.3.62a.3.b: RAN-INFORMATION-ACK RIM Container Contents */
struct bssgp_ran_inf_ack_rim_cont {
	uint8_t app_id;
	uint32_t seq_num;
	uint8_t prot_ver;

	/* Pointer to nested containers */
	const uint8_t *son_trans_app_id;
	size_t son_trans_app_id_len;
};

int bssgp_dec_ran_inf_ack_rim_cont(struct bssgp_ran_inf_ack_rim_cont *cont, const uint8_t *buf, size_t len);
int bssgp_enc_ran_inf_ack_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_ack_rim_cont *cont);

/* 3GPP TS 48.018, table 11.3.62a.4.b: RAN-INFORMATION-ERROR RIM Container Contents */
struct bssgp_ran_inf_err_rim_cont {
	uint8_t app_id;
	uint8_t cause;
	uint8_t prot_ver;

	/* Pointer to nested containers */
	const uint8_t *err_pdu;
	size_t err_pdu_len;
	const uint8_t *son_trans_app_id;
	size_t son_trans_app_id_len;
};

int bssgp_dec_ran_inf_err_rim_cont(struct bssgp_ran_inf_err_rim_cont *cont, const uint8_t *buf, size_t len);
int bssgp_enc_ran_inf_err_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_err_rim_cont *cont);

/* 3GPP TS 48.018, table 11.3.62a.5.b: RAN-INFORMATION-APPLICATION-ERROR RIM Container Contents */
struct bssgp_ran_inf_app_err_rim_cont {
	uint8_t app_id;
	uint32_t seq_num;
	struct bssgp_rim_pdu_ind pdu_ind;
	uint8_t prot_ver;

	/* Pointer to nested containers */
	const uint8_t *app_err_cont;
	size_t app_err_cont_len;
};

int bssgp_dec_ran_inf_app_err_rim_cont(struct bssgp_ran_inf_app_err_rim_cont *cont, const uint8_t *buf, size_t len);
int bssgp_enc_ran_inf_app_err_rim_cont(uint8_t *buf, size_t len, const struct bssgp_ran_inf_app_err_rim_cont *cont);

/* 3GPP TS 48.018, table 11.3.63.1.1: RAN-INFORMATION-REQUEST Application Container coding for NACC */
struct bssgp_ran_inf_req_app_cont_nacc {
	struct {
		struct gprs_ra_id raid;
		uint16_t cid;
	} reprt_cell;
};

int bssgp_dec_ran_inf_req_app_cont_nacc(struct bssgp_ran_inf_req_app_cont_nacc *cont, const uint8_t *buf, size_t len);
int bssgp_enc_ran_inf_req_app_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_ran_inf_req_app_cont_nacc *cont);

/* 3GPP TS 48.018, table 11.3.63.2.1.a: RAN-INFORMATION Application Container coding for NACC */
struct bssgp_ran_inf_app_cont_nacc {
	struct {
		struct gprs_ra_id raid;
		uint16_t cid;
	} reprt_cell;
	bool type_psi;
	uint8_t num_si;
	const uint8_t *si[127];
};

int bssgp_dec_ran_inf_app_cont_nacc(struct bssgp_ran_inf_app_cont_nacc *cont, const uint8_t *buf, size_t len);
int bssgp_enc_ran_inf_app_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_ran_inf_app_cont_nacc *cont);

/* 3GPP TS 48.018, table 11.3.64.1.b, NACC Cause coding */
enum bssgp_nacc_cause {
	BSSGP_NACC_CAUSE_UNSPEC,
	BSSGP_NACC_CAUSE_SYNTAX_ERR,
	BSSGP_NACC_CAUSE_RPRT_CELL_MISSMTCH,
	BSSGP_NACC_CAUSE_SIPSI_TYPE_ERR,
	BSSGP_NACC_CAUSE_SIPSI_LEN_ERR,
	BSSGP_NACC_CAUSE_SIPSI_SET_ERR,
};

/* 3GPP TS 48.018, table 11.3.64.1.a, Application Error Container coding for NACC */
struct bssgp_app_err_cont_nacc {
	enum bssgp_nacc_cause nacc_cause;
	const uint8_t *err_app_cont;
	size_t err_app_cont_len;
};

int bssgp_dec_app_err_cont_nacc(struct bssgp_app_err_cont_nacc *cont, const uint8_t *buf, size_t len);
int bssgp_enc_app_err_cont_nacc(uint8_t *buf, size_t len, const struct bssgp_app_err_cont_nacc *cont);
