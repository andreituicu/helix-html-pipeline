/*
 * Copyright 2021 Adobe. All rights reserved.
 * This file is licensed to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
 * OF ANY KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */

/* eslint-disable max-len */
import crypto from 'crypto';
import { h } from 'hastscript';
import { unified } from 'unified';
import rehypeParse from 'rehype-parse';
import { cleanupHeaderValue } from '@adobe/helix-shared-utils';
import { remove } from 'unist-util-remove';

function appendElement($parent, $el) {
  if ($el) {
    $parent.children.push($el);
  }
}

function createElement(name, ...attrs) {
  // check for empty values
  const properties = {};
  for (let i = 0; i < attrs.length; i += 2) {
    const value = attrs[i + 1];
    if (value === undefined) {
      return null;
    }
    properties[attrs[i]] = value;
  }
  return h(name, properties);
}

function sanitizeJsonLd(jsonLd) {
  const sanitizedJsonLd = jsonLd.replaceAll('<', '&#x3c;').replaceAll('>', '&#x3e;');
  return JSON.stringify(JSON.parse(sanitizedJsonLd.trim()));
}

function parseCSP(csp) {
  const parts = csp.split(';');
  const result = {};
  parts.forEach((part) => {
    const [directive, ...values] = part.trim().split(' ');
    result[directive] = values.join(' ');
  });
  return result;
}

function createAndApplyNonce(res, head, metaCSP, headersCSP) {
  const nonce = crypto.randomBytes(16).toString('base64');
  let scriptNonce = false;
  let styleNonce = false;

  if (metaCSP) {
    const parsedMetaCSP = parseCSP(metaCSP.properties.content);
    scriptNonce ||= parsedMetaCSP['script-src']?.includes('nonce');
    styleNonce ||= parsedMetaCSP['style-src']?.includes('nonce');
    metaCSP.properties.content = metaCSP.properties.content.replaceAll('nonce', `nonce-${nonce}`);
  }

  if (headersCSP) {
    const parsedHeaderCSP = parseCSP(headersCSP);
    scriptNonce ||= parsedHeaderCSP['script-src']?.includes('nonce');
    styleNonce ||= parsedHeaderCSP['style-src']?.includes('nonce');
    res.headers.set('content-security-policy', headersCSP.replaceAll('nonce', `nonce-${nonce}`));
  }

  if (scriptNonce) {
    head.children.forEach(
      (el) => { if (el.tagName === 'script') el.properties.nonce = nonce; },
    );
  }

  if (styleNonce) {
    head.children.forEach(
      (el) => { if (el.tagName === 'style' || (el.tagName === 'link' && el.properties.rel?.[0] === 'stylesheet')) el.properties.nonce = nonce; },
    );
  }
}

function contentSecurityPolicy(res, head) {
  const metaCSP = head.children.find(
    (el) => el.tagName === 'meta' && el.properties?.httpEquiv?.[0]?.toLowerCase() === 'content-security-policy',
  );
  const headersCSP = res.headers.get('content-security-policy');

  if (!metaCSP && !headersCSP) {
    // No CSP defined
    return;
  }

  // CSP with nonce
  if (
    (metaCSP && metaCSP.properties.content.includes('nonce'))
    || (headersCSP && headersCSP.includes('nonce'))
  ) {
    createAndApplyNonce(res, head, metaCSP, headersCSP);
  }

  if (metaCSP && !headersCSP) {
    if (!metaCSP.properties['keep-as-meta']) {
      // if we have a CSP in meta but no CSP in headers, we move the meta CSP to the headers, because it is more secure
      res.headers.set('content-security-policy', metaCSP.properties.content);
      remove(head, null, metaCSP);
    } else {
      // specifically instructed to keep as meta, so we remove the property, because it is not standard HTML
      delete metaCSP.properties['keep-as-meta'];
    }
  }
}

/**
 * @type PipelineStep
 * @param {PipelineState} state
 * @param {PipelineRequest} req
 * @param {PipelineResponse} res
 * @returns {Promise<void>}
 */
export default async function render(state, req, res) {
  const { content } = state;
  const { hast, meta } = content;

  if (state.info.selector === 'plain') {
    // just return body
    res.document = hast;
    return;
  }
  const $head = h('head');
  if (meta.title !== undefined) {
    $head.children.push(h('title', meta.title));
  }

  if (meta.canonical) {
    appendElement($head, createElement('link', 'rel', 'canonical', 'href', meta.canonical));
  }

  let jsonLd;
  for (const [name, value] of Object.entries(meta.page)) {
    if (name.toLowerCase() === 'json-ld') {
      jsonLd = value;
      // eslint-disable-next-line no-continue
      continue;
    }
    const attr = name.includes(':') && !name.startsWith('twitter:') ? 'property' : 'name';
    if (Array.isArray(value)) {
      for (const v of value) {
        appendElement($head, createElement('meta', attr, name, 'content', v));
      }
    } else {
      appendElement($head, createElement('meta', attr, name, 'content', value));
    }
  }
  appendElement($head, createElement('link', 'rel', 'alternate', 'type', 'application/xml+atom', 'href', meta.feed, 'title', `${meta.title} feed`));

  // inject json ld if valid
  if (jsonLd) {
    const props = { type: 'application/ld+json' };
    try {
      jsonLd = sanitizeJsonLd(jsonLd);
    } catch (e) {
      jsonLd = '';
      props['data-error'] = `error in json-ld: ${cleanupHeaderValue(e.message)}`;
    }
    const script = h('script', props, jsonLd);
    $head.children.push(script);
  }

  // inject head.html
  const headHtml = state.config?.head?.html;
  if (headHtml) {
    const $headHtml = await unified()
      .use(rehypeParse, { fragment: true })
      .parse(headHtml);
    contentSecurityPolicy(res, $headHtml);
    $head.children.push(...$headHtml.children);
  }

  res.document = {
    type: 'root',
    children: [
      { type: 'doctype' },
      h('html', [
        $head,
        h('body', [
          h('header', []), // todo: are those still required ?
          h('main', hast),
          h('footer', []), // todo: are those still required ?
        ]),
      ]),
    ],
  };
}
