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
  it('should handle SQL injection attempts securely', async () => {
    const response = await request(app)
      .post('/login')
      .send({ username: "'", password: "anything" });
  
    // This test will FAIL because the app is vulnerable
    expect(response.status).toBe(401); // Should return "Invalid credentials"
    expect(response.body.error).toBe('Invalid credentials');
  });
});

describe('rate limiting', () => {
  it('blocks requests after exceeding the limit', async () => {
    for (let i = 0; i < 100; i++) {
      const res = await request(app).get('/rate-limit-test');
      expect(res.status).toBe(200);
    }
    const blockedRes = await request(app).get('/rate-limit-test');
    expect(blockedRes.status).toBe(429);
    expect(blockedRes.text).toContain('Too many requests');
  });
})

