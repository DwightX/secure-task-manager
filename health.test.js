const request = require('supertest');
const {app,db} = require('./app');
const sqlite3 = require('sqlite3').verbose();


describe('Health Check', () => {
  it('returns 200 OK', async () => {
    const res = await request(app).get('/health');
    expect(res.statusCode).toBe(200);
    expect(res.text).toBe('OK');
  });

  it('returns 200 OK when the database is reachable', async () => {
    // db.close(); // Simmulates the database being unreachable
    const res = await request(app).get('/health');
    expect(res.statusCode).toBe(200);
    expect(res.text).toBe("OK");

  });
});

