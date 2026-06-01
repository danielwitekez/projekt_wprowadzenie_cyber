import { useState, useEffect } from 'react';
import axios from 'axios';
import { Lock, User, ShieldCheck } from 'lucide-react';

const API_URL = "http://127.0.0.1:5000";

function App() {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({ username: '', password: '', totp_code: '' });
  const [message, setMessage] = useState({ text: '', type: '' });
  const [setupUri, setSetupUri] = useState(null);

  // Funkcja obliczająca entropię "na żywo" na froncie
  const getDynamicEntropy = (password) => {
    if (!password) return 0;
    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;

    if (poolSize === 0) return 0;
    const entropy = password.length * Math.log2(poolSize);
    return Math.round(entropy);
  };

  const currentEntropy = getDynamicEntropy(formData.password);

  const getStrengthColor = (entropy) => {
    if (entropy < 45) return '#ef4444'; // Słabe - czerwony
    if (entropy < 75) return '#f59e0b'; // Średnie - pomarańczowy
    return '#22c55e'; // Mocne - zielony
  };

  // Czyścimy komunikaty po czasie
  useEffect(() => {
    if (message.text && message.type === 'error') {
      const timer = setTimeout(() => setMessage({ text: '', type: '' }), 5000);
      return () => clearTimeout(timer);
    }
  }, [message]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const endpoint = isLogin ? "/login" : "/register";

    try {
      const response = await axios.post(`${API_URL}${endpoint}`, formData);

      if (!isLogin) {
        setSetupUri(response.data.setup_uri);
        setMessage({
          text: `Zarejestrowano! Zeskanuj kod QR w aplikacji Google Authenticator.`,
          type: 'success'
        });
      } else {
        setMessage({ text: "Logowanie pomyślne! System przyznał dostęp.", type: 'success' });
        setSetupUri(null);
      }
    } catch (error) {
      setMessage({
        text: error.response?.data?.error || "Wystąpił błąd połączenia",
        type: 'error'
      });
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h2 style={styles.title}>{isLogin ? 'System Logowania' : 'Tworzenie Konta'}</h2>

        {message.text && (
          <div style={{
            ...styles.alert,
            backgroundColor: message.type === 'error' ? '#fee2e2' : '#dcfce7',
            color: message.type === 'error' ? '#991b1b' : '#166534'
          }}>
            {message.text}
          </div>
        )}

        <form onSubmit={handleSubmit} style={styles.form}>
          {/* LOGIN / USERNAME */}
          <div style={styles.inputGroup}>
            <User size={20} color="#6b7280" />
            <input
              type="text" placeholder="Nazwa użytkownika" required
              value={formData.username}
              onChange={(e) => setFormData({...formData, username: e.target.value})}
              style={styles.input}
            />
          </div>

          {/* PASSWORD */}
          <div style={styles.inputGroup}>
            <Lock size={20} color="#6b7280" />
            <input
              type="password" placeholder="Hasło" required
              value={formData.password}
              onChange={(e) => setFormData({...formData, password: e.target.value})}
              style={styles.input}
            />
          </div>

          {/* DYNAMICZNY WSKAŹNIK ENTROPII (Tylko Rejestracja) */}
          {!isLogin && formData.password.length > 0 && (
            <div style={{ marginTop: '-5px', marginBottom: '10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginBottom: '4px' }}>
                <span style={{color: '#4b5563'}}>Siła: {currentEntropy} bitów</span>
                <span style={{ color: getStrengthColor(currentEntropy), fontWeight: 'bold' }}>
                   {currentEntropy < 45 ? 'SŁABE' : currentEntropy < 75 ? 'ŚREDNIE' : 'MOCNE'}
                </span>
              </div>
              <div style={styles.progressBarBg}>
                <div style={{
                  ...styles.progressBarFill,
                  width: `${Math.min((currentEntropy / 120) * 100, 100)}%`,
                  backgroundColor: getStrengthColor(currentEntropy)
                }} />
              </div>
            </div>
          )}

          {/* KOD QR (Po rejestracji) */}
          {setupUri && !isLogin && (
            <div style={styles.qrContainer}>
              <p style={{fontSize: '12px', marginBottom: '10px', textAlign: 'center', color: '#374151', fontWeight: 'bold'}}>
                ZESKANUJ KOD QR (2FA):
              </p>
              <div style={styles.qrCode}>
                <img
                  src={`https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(setupUri)}`}
                  alt="2FA QR Code"
                  style={{ display: 'block', width: '150px', height: '150px' }}
                />
              </div>
            </div>
          )}

          {/* POLE TOTP (Tylko Logowanie) */}
          {isLogin ? (
            <div style={styles.inputGroup}>
              <ShieldCheck size={20} color="#6b7280" />
              <input
                type="text" placeholder="Kod z aplikacji (6 cyfr)"
                value={formData.totp_code}
                onChange={(e) => setFormData({...formData, totp_code: e.target.value})}
                style={styles.input}
              />
            </div>
          ) : (
            <p style={styles.hint}>Wymagania: 12+ znaków, A-Z, 0-9, !@#</p>
          )}

          <button type="submit" style={styles.button}>
            {isLogin ? 'ZALOGUJ SIĘ' : 'ZAREJESTRUJ MNIE'}
          </button>
        </form>

        <button
          onClick={() => {
            setIsLogin(!isLogin);
            setMessage({text:'', type:''});
            setSetupUri(null);
            setFormData({ username: '', password: '', totp_code: '' });
          }}
          style={styles.switchButton}
        >
          {isLogin ? 'Nie masz konta? Załóż je tutaj' : 'Masz już konto? Zaloguj się'}
        </button>
      </div>
    </div>
  );
}

const styles = {
  container: { display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', backgroundColor: '#f3f4f6', margin: 0 },
  card: { backgroundColor: 'white', padding: '2.5rem', borderRadius: '16px', boxShadow: '0 10px 25px rgba(0,0,0,0.1)', width: '380px' },
  title: { textAlign: 'center', color: '#111827', marginBottom: '2rem', fontFamily: 'sans-serif', fontSize: '22px', fontWeight: '800' },
  form: { display: 'flex', flexDirection: 'column', gap: '1.2rem' },
  inputGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    border: '1px solid #d1d5db',
    padding: '12px',
    borderRadius: '8px',
    backgroundColor: '#ffffff'
  },
  input: { border: 'none', outline: 'none', width: '100%', fontSize: '15px', backgroundColor: '#ffffff', color: '#111827' },
  button: { backgroundColor: '#2563eb', color: 'white', padding: '14px', borderRadius: '8px', border: 'none', cursor: 'pointer', fontSize: '15px', fontWeight: 'bold', transition: 'background 0.2s' },
  switchButton: { marginTop: '1.5rem', background: 'none', border: 'none', color: '#2563eb', cursor: 'pointer', width: '100%', textAlign: 'center', fontSize: '14px' },
  alert: { padding: '12px', borderRadius: '8px', marginBottom: '1.5rem', fontSize: '13px', border: '1px solid #eee', textAlign: 'center' },
  hint: { fontSize: '11px', color: '#6b7280', margin: '0', textAlign: 'center' },
  qrContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    backgroundColor: '#f9fafb',
    padding: '15px',
    borderRadius: '12px',
    border: '1px solid #e5e7eb'
  },
  qrCode: {
    backgroundColor: 'white',
    padding: '10px',
    borderRadius: '8px',
    boxShadow: '0 4px 6px rgba(0,0,0,0.05)'
  },
  progressBarBg: {
    width: '100%',
    height: '6px',
    backgroundColor: '#e5e7eb',
    borderRadius: '3px',
    overflow: 'hidden'
  },
  progressBarFill: {
    height: '100%',
    transition: 'width 0.4s ease-out, background-color 0.4s ease'
  },
};

export default App;