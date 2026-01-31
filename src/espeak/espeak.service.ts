import { Injectable, Logger } from '@nestjs/common';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { unlink, access, writeFile, readFile } from 'fs/promises';
import { constants } from 'fs';

const execFileAsync = promisify(execFile);

@Injectable()
export class EspeakService {
  private readonly log = new Logger(EspeakService.name);
  private readonly TTL_SECONDS = 300; // 5 minutes
  private readonly cleanupTimers = new Map<string, NodeJS.Timeout>();

  constructor() {}

  /**
   * Generate audio file for a captcha challenge
   * @param challengeId The challenge ID
   * @param text The text to speak
   * @param language Language code (e.g., 'en', 'de')
   * @returns Path to the generated audio file
   */
  async generateAudio(
    challengeId: string,
    text: string,
    language: string = 'en',
  ): Promise<string> {
    const lockFile = `/tmp/${challengeId}.lock`;
    const finalPath = `/tmp/${challengeId}.wav`;
    const espeakPath = `/tmp/${challengeId}.espeak.wav`;

    try {
      // Check if file already exists
      try {
        await access(finalPath, constants.R_OK);
        this.log.debug(`Audio file already exists: ${finalPath}`);
        return finalPath;
      } catch {
        // File doesn't exist, continue with generation
      }

      // Try to acquire lock by creating lock file
      const lockAcquired = await this.acquireLock(lockFile);

      if (!lockAcquired) {
        // Another process is generating this audio, wait and check for the file
        this.log.debug(
          `Another process is generating audio for ${challengeId}, waiting...`,
        );

        // Poll for up to 30 seconds
        for (let i = 0; i < 30; i++) {
          await new Promise((resolve) => setTimeout(resolve, 1000));
          try {
            await access(finalPath, constants.R_OK);
            this.log.debug(`Audio file ready: ${finalPath}`);
            return finalPath;
          } catch {
            // File not ready yet, check if lock still exists
            try {
              await access(lockFile, constants.R_OK);
              // Lock still exists, continue waiting
            } catch {
              // Lock disappeared but no file - something went wrong
              throw new Error(
                'Audio generation failed (lock released without file)',
              );
            }
          }
        }

        throw new Error('Audio generation timed out');
      }

      this.log.debug(
        `Generating audio for challenge ${challengeId}, language: ${language}`,
      );

      // Generate audio with espeak
      await this.generateWithEspeak(text, language, espeakPath);

      // Distort audio with sox
      await this.distortWithSox(espeakPath, finalPath);

      // Clean up undistorted file
      try {
        await unlink(espeakPath);
      } catch (error) {
        this.log.warn(`Failed to delete espeak file: ${error}`);
      }

      // Schedule file cleanup
      this.scheduleCleanup(challengeId, finalPath, lockFile);

      // Release lock
      await this.releaseLock(lockFile);

      this.log.debug(`Audio generated successfully: ${finalPath}`);
      return finalPath;
    } catch (error) {
      // Clean up on error
      await this.releaseLock(lockFile);

      // Try to clean up any partial files
      try {
        await unlink(espeakPath);
      } catch {
        // Ignore cleanup errors
      }
      try {
        await unlink(finalPath);
      } catch {
        // Ignore cleanup errors
      }

      this.log.error(`Failed to generate audio: ${error}`);
      throw error;
    }
  }

  /**
   * Acquire lock using lock file
   * @returns true if lock was acquired, false if already locked
   */
  private async acquireLock(lockFile: string): Promise<boolean> {
    try {
      // Check if lock file exists
      await access(lockFile, constants.F_OK);

      // Lock file exists, check if it's stale (older than 30 seconds)
      const lockContent = await readFile(lockFile, 'utf-8');
      const lockTime = parseInt(lockContent, 10);
      const now = Date.now();

      if (now - lockTime > 30000) {
        // Stale lock, remove it and acquire
        this.log.warn(`Removing stale lock file: ${lockFile}`);
        await unlink(lockFile);
      } else {
        // Active lock
        return false;
      }
    } catch {
      // Lock file doesn't exist, we can acquire it
    }

    try {
      // Create lock file with current timestamp
      await writeFile(lockFile, Date.now().toString(), { flag: 'wx' });
      return true;
    } catch {
      // Race condition: another process created the lock
      return false;
    }
  }

  /**
   * Release lock by deleting lock file
   */
  private async releaseLock(lockFile: string): Promise<void> {
    try {
      await unlink(lockFile);
    } catch (error) {
      this.log.warn(`Failed to release lock file ${lockFile}: ${error}`);
    }
  }

  /**
   * Generate audio using espeak
   */
  private async generateWithEspeak(
    text: string,
    language: string,
    outputPath: string,
  ): Promise<void> {
    try {
      // Split "1234" into "1 2 3 4" so espeak treats them as separate words
      const spacedText = text.split('').join(' ');

      const args = [
        `-v${language}`,
        '-s',
        '140', // Slightly slower speed helps clarity
        '-g',
        '15', // Word gap: pause duration (units of 10ms). 15 = 150ms gap.
        '-p',
        '50',
        '-a',
        '100',
        '-w',
        outputPath,
        spacedText,
      ];

      await execFileAsync('espeak', args);
    } catch (error) {
      this.log.error(`Espeak generation failed: ${error}`);
      throw error;
    }
  }

  /**
   * Distort audio using sox to make it harder to solve programmatically
   */
  private async distortWithSox(
    inputPath: string,
    outputPath: string,
  ): Promise<void> {
    try {
      // Apply multiple effects to distort the audio:
      // - Add background noise
      // - Apply reverb
      // - Add echo
      // - Change pitch slightly
      // - Apply overdrive for slight distortion
      const args = [
        inputPath, // Input file
        outputPath, // Output file
        'vol',
        '0.9', // Slightly lower volume to prevent clipping
        'overdrive',
        '10',
        'echo',
        '0.8',
        '0.88',
        '60',
        '0.4',
        'pitch',
        '50',
        'reverb',
        '50',
        // Use 'synth' to ADD noise rather than replace
        'synth',
        'whitenoise',
        'amod',
        '0.05',
        'norm',
        '-3',
      ];

      await execFileAsync('sox', args);
      this.log.debug(`Sox distorted audio: ${outputPath}`);
    } catch (error) {
      this.log.error(`Sox distortion failed: ${error}`);
      throw new Error(
        `Sox distortion failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  /**
   * Schedule file cleanup after TTL
   */
  private scheduleCleanup(
    challengeId: string,
    filePath: string,
    lockFile: string,
  ): void {
    // Cancel existing timer if any
    const existingTimer = this.cleanupTimers.get(challengeId);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    // Schedule new cleanup
    const timer = setTimeout(() => {
      void (async () => {
        try {
          await unlink(filePath);
          // Also clean up lock file if it still exists
          try {
            await unlink(lockFile);
          } catch {
            // Ignore lock file cleanup errors
          }
          this.cleanupTimers.delete(challengeId);
          this.log.debug(`Cleaned up audio file: ${filePath}`);
        } catch (error) {
          this.log.warn(`Failed to clean up audio file ${filePath}: ${error}`);
        }
      })();
    }, this.TTL_SECONDS * 1000);

    this.cleanupTimers.set(challengeId, timer);
  }

  /**
   * Clean up all scheduled timers on module destroy
   */
  onModuleDestroy(): void {
    this.cleanupTimers.forEach((timer) => clearTimeout(timer));
    this.cleanupTimers.clear();
  }

  /**
   * Get the audio file path if it exists
   */
  async getAudioPath(challengeId: string): Promise<string | null> {
    const finalPath = `/tmp/${challengeId}.wav`;

    try {
      await access(finalPath, constants.R_OK);
      return finalPath;
    } catch {
      return null;
    }
  }
}
