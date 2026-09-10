import { describe, expect, it } from 'vitest';
import { deriveProfileId, normalizeWizardEndpoint } from '../../src/cli/router-wizard-helpers.js';

describe('wizard profile ID derivation', () => {
  it.each([
    ['Home Router', 'home-router'],
    ['  Café № 2  ', 'cafe-2'],
    ['Домашний роутер', 'domashniy-router'],
    ['Київський маршрутизатор', 'kiyivskiy-marshrutizator'],
    ['123 / 東京', 'router'],
    ['', 'router']
  ])('derives %s as %s', (name, expected) => {
    expect(deriveProfileId(name)).toBe(expected);
  });

  it('uses deterministic collision suffixes', () => {
    expect(deriveProfileId('Home', ['home', 'home-2', 'other', 'home-4'])).toBe('home-3');
    expect(deriveProfileId('!!!', new Set(['router', 'router-2']))).toBe('router-3');
  });

  it('truncates IDs and their suffixed variants to the registry limit', () => {
    const name = `A${'b'.repeat(80)}`;
    const first = deriveProfileId(name);
    const second = deriveProfileId(name, [first]);
    expect(first).toHaveLength(64);
    expect(second).toHaveLength(64);
    expect(second).toMatch(/-2$/);
    expect(first).toMatch(/^[a-z][a-z0-9_-]{0,63}$/);
    expect(second).toMatch(/^[a-z][a-z0-9_-]{0,63}$/);
  });
});

describe('wizard remote endpoint normalization', () => {
  it.each([
    ['router.example.test', 'https://router.example.test/rci/'],
    ['router.example.test/rci', 'https://router.example.test/rci/'],
    ['router.example.test/rci/', 'https://router.example.test/rci/'],
    ['https://router.example.test', 'https://router.example.test/rci/'],
    ['https://router.example.test/', 'https://router.example.test/rci/'],
    ['https://router.example.test/rci', 'https://router.example.test/rci/'],
    ['https://router.example.test/rci/', 'https://router.example.test/rci/'],
    ['https://router.example.test:8443/rci/', 'https://router.example.test:8443/rci/']
  ])('normalizes %s', (input, expected) => {
    expect(normalizeWizardEndpoint(input, 'remote')).toBe(expected);
  });

  it('upgrades explicit HTTP only for KeenDNS hosts', () => {
    expect(normalizeWizardEndpoint('http://my-router.keenetic.pro', 'remote')).toBe('https://my-router.keenetic.pro/rci/');
    expect(normalizeWizardEndpoint('http://sub.my-router.keenetic.pro/rci', 'remote')).toBe('https://sub.my-router.keenetic.pro/rci/');
    expect(normalizeWizardEndpoint('http://rci.example.netcraze.club', 'remote')).toBe('https://rci.example.netcraze.club/rci/');
    expect(() => normalizeWizardEndpoint('http://router.example.test', 'remote')).toThrow(/HTTPS/);
    expect(() => normalizeWizardEndpoint('http://keenetic.pro', 'remote')).toThrow(/HTTPS/);
  });

  it.each([
    ['https://user:password@router.example.test', /credentials/],
    ['router.example.test?secret=value', /query or fragment/],
    ['https://router.example.test/#status', /query or fragment/],
    ['https://router.example.test/admin', /path/],
    ['ftp://router.example.test/rci/', /HTTPS/],
    ['', /required/]
  ])('rejects %s', (input, message) => {
    expect(() => normalizeWizardEndpoint(input, 'remote')).toThrow(message);
  });

  it('does not remove or replace hostname labels', () => {
    expect(normalizeWizardEndpoint('http://rci.house.keenetic.pro/rci/', 'remote'))
      .toBe('https://rci.house.keenetic.pro/rci/');
    expect(normalizeWizardEndpoint('http://rci.house.netcraze.club/rci/', 'remote'))
      .toBe('https://rci.house.netcraze.club/rci/');
  });

  it('trims LAN addresses and requires a value', () => {
    expect(normalizeWizardEndpoint('  192.0.2.1  ', 'lan')).toBe('192.0.2.1');
    expect(normalizeWizardEndpoint(' router.lan ', 'lan')).toBe('router.lan');
    expect(() => normalizeWizardEndpoint('   ', 'lan')).toThrow(/required/);
  });

  it.each([
    'http://router.lan', 'user:password@router.lan', 'router.lan/path',
    'router.lan?token=value', 'router.lan#fragment', 'router\n.evil', 'router\t.evil', 'router\u202e.evil'
  ])('rejects unsafe LAN endpoint %s', input => {
    expect(() => normalizeWizardEndpoint(input, 'lan')).toThrow();
  });
});
