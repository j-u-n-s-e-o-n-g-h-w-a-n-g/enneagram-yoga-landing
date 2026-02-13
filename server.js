require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { getPool, initDB, isDBReady, getDbUrl } = require('./db');
const { generateTempPassword } = require('./words');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ===================== CONFIG (환경변수 통합) =====================
const CONFIG = {
  PASS_PRICE: parseInt(process.env.PASS_PRICE) || 99000,
  PASS_CLASSES: parseInt(process.env.PASS_CLASSES) || 12,
  PASS_MONTHS: parseInt(process.env.PASS_MONTHS) || 3,
  BANK_NAME: process.env.BANK_NAME || '농협',
  BANK_ACCOUNT: process.env.BANK_ACCOUNT || '312-0025-5524-11',
  BANK_HOLDER: process.env.BANK_HOLDER || '황준성',
  HOST_EMAIL: process.env.HOST_EMAIL || 'junseong@junseonghwang.com',
  SOLAPI_API_KEY: process.env.SOLAPI_API_KEY || 'NCS4FNOFBWYK96ZI',
  SOLAPI_API_SECRET: process.env.SOLAPI_API_SECRET || 'E6SA8I6NCT04MKTQN8TX0Y4SSGHEJMGR',
  SOLAPI_SENDER: process.env.SOLAPI_SENDER || '07079548182',
  RESEND_API_KEY: process.env.RESEND_API_KEY || 're_RfLPds6p_GxskQTJaTUCpn4HHengcj64y',
};