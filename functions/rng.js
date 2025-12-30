const crypto = require('crypto');

function randomTicketNumber(totalTickets = 500) {
    const max = Math.max(1, Math.floor(totalTickets));
    return crypto.randomInt(1, max + 1);
}

module.exports = { randomTicketNumber };
