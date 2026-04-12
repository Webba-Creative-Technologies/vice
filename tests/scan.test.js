// tests/scan.test.js
import { validateAndResolveDomain } from '../scan.js';

describe('VICE Scan Tests', () => {
  describe('validateAndResolveDomain', () => {
    it('should validate a valid domain', async () => {
      const domain = 'example.com';
      await expect(validateAndResolveDomain(domain)).resolves.not.toThrow();
    });

    it('should reject an invalid domain', async () => {
      const domain = 'invalid-domain';
      await expect(validateAndResolveDomain(domain)).rejects.toThrow('TLD invalide ou domaine malformé');
    });

    it('should reject a private IP', async () => {
      const domain = '192.168.1.1';
      await expect(validateAndResolveDomain(domain)).rejects.toThrow('Accès refusé : adresse IP privée/interne');
    });

    it('should reject a blocked target', async () => {
      const domain = 'example.com';
      // Assuming example.com is in the blocked targets
      await expect(validateAndResolveDomain(domain)).rejects.toThrow('Ce domaine est sur la liste de blocage');
    });
  });
});