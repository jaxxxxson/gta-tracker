const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());
app.use(cors());

const supabaseUrl = process.env.SUPABASE_URL || 'https://wyfkpmoyaeilxsgvnwgd.supabase.co';
const supabaseKey = process.env.SUPABASE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Ind5ZmtwbW95YWVpbHhzZ3Zud2dkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDEyMzg2Mzh9.u8Y9aZgN_n2P3Kx7qQ0tL5V8W1m3J2s6X4v5b9n2m1s';
const supabase = createClient(supabaseUrl, supabaseKey);

app.get('/api/ping', (req, res) => {
    res.json({ success: true, message: 'Server is awake' });
});

app.post('/api/verify-key', async (req, res) => {
    const { key, device_id } = req.body;

    if (!key || !device_id) {
        return res.status(400).json({ success: false, error: 'Не указан ключ или ID устройства' });
    }

    try {
        const { data: keyRecord, error } = await supabase
            .from('keys')
            .select('*')
            .eq('key_string', key)
            .single();

        if (error || !keyRecord) {
            return res.status(404).json({ success: false, error: 'Ключ не найден' });
        }

        if (new Date(keyRecord.expires_at) < new Date()) {
            return res.status(403).json({ success: false, error: 'Срок действия ключа истек' });
        }

        if (!keyRecord.device_id) {
            await supabase
                .from('keys')
                .update({ device_id: device_id })
                .eq('key_string', key);
        } else if (keyRecord.device_id !== device_id) {
            return res.status(403).json({ success: false, error: 'Этот ключ уже активирован на другом устройстве!' });
        }

        res.json({ success: true, expires_at: keyRecord.expires_at });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Ошибка сервера' });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
