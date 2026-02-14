const crypto = require('crypto');

module.exports = function(CONFIG) {
  async function issueCashReceipt({ phone, name, email, amount, memo }) {
    const LinkID = CONFIG.POPBILL_LINK_ID;
    const SecretKey = CONFIG.POPBILL_SECRET_KEY;
    const CorpNum = CONFIG.POPBILL_CORP_NUM;
    const bodyObj = { access_id: CorpNum, scope: ['member', '140'] };
    const bodyJson = JSON.stringify(bodyObj);
    const timestamp = new Date().toISOString();
    const bodyHash = crypto.createHash('sha256').update(bodyJson).digest('base64');
    const uri = '/POPBILL/Token';
    const digestTarget = 'POST\n' + bodyHash + '\n' + timestamp + '\n2.0\n' + uri;
    const sig = crypto.createHmac('sha256', Buffer.from(SecretKey, 'base64')).update(digestTarget).digest('base64');
    const tokenResp = await fetch('https://auth.linkhub.co.kr' + uri, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-lh-date': timestamp, 'x-lh-version': '2.0', 'Authorization': 'LINKHUB ' + LinkID + ' ' + sig },
      body: bodyJson
    });
    const tokenData = await tokenResp.json();
    if (!tokenData.session_token) return { success: false, error: 'Popbill 토큰 실패', tokenData };

    const rawAmount = Number(amount);
    const receiptAmount = Math.min(rawAmount, CONFIG.PASS_PRICE);
    const tax = Math.round(receiptAmount / 11);
    const supply = receiptAmount - tax;
    const mgtKey = 'YOGA-' + Date.now();
    const identityNum = String(phone).replace(/[^0-9]/g, '');
    const custPhone = identityNum.startsWith('0') ? identityNum : '0' + identityNum;
    const cashbill = {
      mgtKey, tradeType: '승인거래', tradeUsage: '소득공제용', taxationType: '과세', tradeOpt: '일반',
      identityNum: custPhone, franchiseCorpNum: CorpNum, franchiseCorpName: '에니어그램 클럽',
      franchiseCEOName: '황준성', franchiseAddr: '제주도 서귀포시 서호중앙로55 유포리아 C동 319호',
      franchiseTEL: CONFIG.SOLAPI_SENDER, customerName: name, itemName: '데일리 요가 클래스',
      orderNumber: mgtKey, email: email || '', hp: custPhone,
      supplyCost: String(supply), tax: String(tax), serviceFee: '0', totalAmount: String(receiptAmount),
      smssendYN: false, memo: memo || (rawAmount < CONFIG.PASS_PRICE ? '자동발행 (부족입금 ' + rawAmount.toLocaleString() + '원)' : rawAmount > CONFIG.PASS_PRICE ? '자동발행 (초과입금, ' + CONFIG.PASS_PRICE.toLocaleString() + '원 발행)' : '자동발행')
    };
    const issueResp = await fetch('https://popbill.linkhub.co.kr/Cashbill', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json;charset=utf-8', 'Authorization': 'Bearer ' + tokenData.session_token, 'X-HTTP-Method-Override': 'ISSUE', 'User-Agent': 'NODEJS POPBILL SDK' },
      body: JSON.stringify(cashbill)
    });
    const issueResult = await issueResp.json();
    const success = issueResp.ok && (issueResult.code === 1 || issueResult.code === undefined);
    return { success, mgtKey, receiptAmount, issueResult };
  }

  return { issueCashReceipt };
};
