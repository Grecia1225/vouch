/** Account lockout after repeated failed logins (slows down password guessing). */
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;

const isLocked = (user, now = Date.now()) => !!(user && user.lockedUntil && new Date(user.lockedUntil).getTime() > now);
const afterFailure = (user, now = Date.now()) => {
  const fails = ((user && user.failedLogins) || 0) + 1;
  return fails >= MAX_FAILS
    ? { failedLogins: 0, lockedUntil: new Date(now + LOCK_MS), locked: true }
    : { failedLogins: fails, lockedUntil: null, locked: false };
};
const afterSuccess = () => ({ failedLogins: 0, lockedUntil: null });
const minutesLeft = (user, now = Date.now()) => Math.max(1, Math.ceil((new Date(user.lockedUntil).getTime() - now) / 60000));

module.exports = { MAX_FAILS, LOCK_MS, isLocked, afterFailure, afterSuccess, minutesLeft };
