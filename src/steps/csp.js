/*
 * Copyright 2024 Adobe. All rights reserved.
 * This file is licensed to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
 * OF ANY KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
import crypto from 'crypto';
import { select, selectAll } from 'hast-util-select';
import { remove } from 'unist-util-remove';

function parseCSP(csp) {
  const parts = csp.split(';');
  const result = {};
  parts.forEach((part) => {
    const [directive, ...values] = part.trim().split(' ');
    result[directive] = values.join(' ');
  });
  return result;
}

function shouldApplyNonce(csp) {
  const parsedCSP = parseCSP(csp);
  return {
    scriptNonce: parsedCSP['script-src']?.includes('nonce'),
    styleNonce: parsedCSP['style-src']?.includes('nonce'),
  };
}

function createAndApplyNonce(res, tree, metaCSP, headersCSP) {
  const nonce = crypto.randomBytes(16).toString('base64');
  let scriptNonceResult = false;
  let styleNonceResult = false;

  if (metaCSP) {
    const { scriptNonce, styleNonce } = shouldApplyNonce(metaCSP.properties.content);
    scriptNonceResult ||= scriptNonce;
    styleNonceResult ||= styleNonce;
    metaCSP.properties.content = metaCSP.properties.content.replaceAll('nonce', `nonce-${nonce}`);
  }

  if (headersCSP) {
    const { scriptNonce, styleNonce } = shouldApplyNonce(headersCSP);
    scriptNonceResult ||= scriptNonce;
    styleNonceResult ||= styleNonce;
    res.headers.set('content-security-policy', headersCSP.replaceAll('nonce', `nonce-${nonce}`));
  }

  if (scriptNonceResult) {
    selectAll('script', tree).forEach((el) => {
      el.properties.nonce = nonce;
    });
  }

  if (styleNonceResult) {
    selectAll('style', tree).forEach((el) => {
      el.properties.nonce = nonce;
    });
    selectAll('link[rel=stylesheet]', tree).forEach((el) => {
      el.properties.nonce = nonce;
    });
  }
}

export function checkResponseBodyForMetaBasedCSP(res) {
  return res.body?.includes('http-equiv="content-security-policy"')
    || res.body?.includes('http-equiv="Content-Security-Policy"');
}

export function getMetaCSP(tree) {
  return select('meta[http-equiv="content-security-policy"]', tree)
    || select('meta[http-equiv="Content-Security-Policy"]', tree);
}

export function getHeaderCSP(res) {
  return res.headers.get('content-security-policy');
}

export function contentSecurityPolicy(res, tree) {
  const metaCSP = getMetaCSP(tree);
  const headersCSP = getHeaderCSP(res);

  if (!metaCSP && !headersCSP) {
    // No CSP defined
    return;
  }

  // CSP with nonce
  if (
    (metaCSP && metaCSP.properties.content.includes('nonce'))
    || (headersCSP && headersCSP.includes('nonce'))
  ) {
    createAndApplyNonce(res, tree, metaCSP, headersCSP);
  }

  if (metaCSP && !headersCSP) {
    if (!metaCSP.properties['keep-as-meta']) {
      // if we have a CSP in meta but no CSP in headers
      // we move the meta CSP to the headers, because it is more secure
      res.headers.set('content-security-policy', metaCSP.properties.content);
      remove(tree, null, metaCSP);
    } else {
      // specifically instructed to keep as meta,
      // so we remove the property, because it is not standard HTML
      delete metaCSP.properties['keep-as-meta'];
    }
  }
}
