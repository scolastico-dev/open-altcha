import { Injectable, Logger } from '@nestjs/common';
import { BaseConfigService } from '../config/base.config';
import { Request } from 'express';

@Injectable()
export class IpService {
  private readonly log = new Logger(IpService.name);

  constructor(private readonly config: BaseConfigService) {}

  extractIp(request: Request): string {
    if (this.config.trustedIpHeader) {
      // Try to get IP from trusted header
      const headerValue =
        request.headers[this.config.trustedIpHeader.toLowerCase()];
      if (headerValue) {
        // If it's a comma-separated list (e.g., X-Forwarded-For), take the first one
        const ip = Array.isArray(headerValue)
          ? headerValue[0]
          : headerValue.split(',')[0].trim();
        this.log.debug(
          `Extracted IP ${ip} from trusted header ${this.config.trustedIpHeader}`,
        );
        return this.stripIPv6(ip);
      }
    }

    // Fallback to request IP
    const ip = request.ip || request.socket?.remoteAddress;
    if (!ip) throw new Error('Unable to extract IP address from request');
    this.log.debug(`Extracted IP ${ip} from request`);
    return this.stripIPv6(ip);
  }

  /**
   * Strip IPv6 addresses from a provided IP string (public method).
   * This is useful when you receive an IP from an external source and need to apply the same stripping logic.
   */
  stripIp(ip: string): string {
    return this.stripIPv6(ip);
  }

  /**
   * Strip IPv6 addresses by removing the specified number of bits from the end.
   * This is useful for privacy and rate limiting, as many ISPs assign /64 prefixes.
   * IPv4 addresses are returned unchanged.
   */
  private stripIPv6(ip: string): string {
    // Check if IPv6 stripping is enabled
    if (!this.config.ipv6StripBits || this.config.ipv6StripBits === 0) {
      return ip;
    }

    // Check if it's an IPv6 address (contains colons)
    if (!ip.includes(':')) {
      return ip;
    }

    try {
      // Normalize IPv6 address by expanding it to full form
      const expandedIP = this.expandIPv6(ip);
      if (!expandedIP) {
        return ip;
      }

      // Calculate how many nibbles (4-bit groups) to zero out
      // Each nibble is 4 bits, so divide stripBits by 4
      const nibblesToZero = Math.floor(this.config.ipv6StripBits / 4);

      // Split into groups
      const groups = expandedIP.split(':');

      // Each group is 16 bits (4 nibbles), total 8 groups = 128 bits
      // Calculate which groups to zero out
      const totalNibbles = groups.length * 4; // 32 nibbles total
      const keepNibbles = totalNibbles - nibblesToZero;

      // Convert nibbles back to groups
      const keepGroups = Math.floor(keepNibbles / 4);
      const partialGroupNibbles = keepNibbles % 4;

      // Build the stripped IP
      const strippedGroups = groups.slice(0, keepGroups);

      // Handle partial group if needed
      if (partialGroupNibbles > 0 && keepGroups < groups.length) {
        const partialGroup = groups[keepGroups];
        const keepChars = partialGroupNibbles;
        const maskedGroup = partialGroup.substring(0, keepChars).padEnd(4, '0');
        strippedGroups.push(maskedGroup);
      }

      // Fill remaining groups with zeros
      while (strippedGroups.length < 8) {
        strippedGroups.push('0000');
      }

      const strippedIP = strippedGroups.join(':');
      this.log.debug(
        `Stripped IPv6 from ${ip} to ${strippedIP} (${this.config.ipv6StripBits} bits)`,
      );

      return this.compressIPv6(strippedIP);
    } catch (error) {
      this.log.warn(
        `Failed to strip IPv6 address ${ip}: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      return ip;
    }
  }

  /**
   * Expand abbreviated IPv6 address to full form.
   */
  private expandIPv6(ip: string): string | null {
    try {
      // Remove IPv4 suffix if present (e.g., ::ffff:192.0.2.1)
      let addr = ip;
      const ipv4Match = ip.match(/:((\d+\.){3}\d+)$/);
      if (ipv4Match) {
        // Convert IPv4 to hex
        const ipv4Parts = ipv4Match[1].split('.');
        const hex1 = (parseInt(ipv4Parts[0]) * 256 + parseInt(ipv4Parts[1]))
          .toString(16)
          .padStart(4, '0');
        const hex2 = (parseInt(ipv4Parts[2]) * 256 + parseInt(ipv4Parts[3]))
          .toString(16)
          .padStart(4, '0');
        addr = ip.replace(ipv4Match[0], `:${hex1}:${hex2}`);
      }

      // Split by ::
      const parts = addr.split('::');

      if (parts.length > 2) {
        return null; // Invalid IPv6
      }

      let groups: string[];

      if (parts.length === 2) {
        const left = parts[0] ? parts[0].split(':') : [];
        const right = parts[1] ? parts[1].split(':') : [];
        const missing = 8 - left.length - right.length;
        const middle: string[] = Array<string>(missing).fill('0000');
        groups = [...left, ...middle, ...right];
      } else {
        groups = parts[0].split(':');
      }

      // Pad each group to 4 characters
      const expanded = groups.map((g) => g.padStart(4, '0')).join(':');

      return expanded;
    } catch {
      return null;
    }
  }

  /**
   * Compress IPv6 address using :: notation.
   */
  private compressIPv6(ip: string): string {
    try {
      // Find longest sequence of consecutive zero groups
      const groups = ip.split(':');
      let longestZeroStart = -1;
      let longestZeroLength = 0;
      let currentZeroStart = -1;
      let currentZeroLength = 0;

      for (let i = 0; i < groups.length; i++) {
        if (groups[i] === '0000' || groups[i] === '0') {
          if (currentZeroStart === -1) {
            currentZeroStart = i;
            currentZeroLength = 1;
          } else {
            currentZeroLength++;
          }
        } else {
          if (currentZeroLength > longestZeroLength) {
            longestZeroStart = currentZeroStart;
            longestZeroLength = currentZeroLength;
          }
          currentZeroStart = -1;
          currentZeroLength = 0;
        }
      }

      // Check last sequence
      if (currentZeroLength > longestZeroLength) {
        longestZeroStart = currentZeroStart;
        longestZeroLength = currentZeroLength;
      }

      // Compress if we found a sequence
      if (longestZeroLength > 1) {
        const before = groups
          .slice(0, longestZeroStart)
          .map((g) => g.replace(/^0+/, '') || '0');
        const after = groups
          .slice(longestZeroStart + longestZeroLength)
          .map((g) => g.replace(/^0+/, '') || '0');

        if (before.length === 0 && after.length === 0) {
          return '::';
        } else if (before.length === 0) {
          return '::' + after.join(':');
        } else if (after.length === 0) {
          return before.join(':') + '::';
        } else {
          return before.join(':') + '::' + after.join(':');
        }
      }

      // No compression, just remove leading zeros
      return groups.map((g) => g.replace(/^0+/, '') || '0').join(':');
    } catch {
      return ip;
    }
  }
}
