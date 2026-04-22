import torch
import torch.nn as nn
import torch.nn.functional as F

class URLNetModern(nn.Module):
    def __init__(self, char_vocab_size, num_lexical_features, emb_dim=32):
        super(URLNetModern, self).__init__()
        
        # 1. Nhánh xử lý Ký tự (Character-level CNN)
        self.char_embed = nn.Embedding(char_vocab_size, emb_dim)
        self.convs = nn.ModuleList([
            nn.Conv1d(emb_dim, 256, k) for k in [3, 4, 5, 6]
        ])
        
        # 2. Nhánh xử lý Đặc trưng Lexical (MLP)
        self.lexical_fc = nn.Sequential(
            nn.Linear(num_lexical_features, 64),
            nn.ReLU()
        )
        
        # 3. Lớp kết hợp cuối cùng
        self.fc_final = nn.Sequential(
            nn.Linear(256 * 4 + 64, 512),
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(512, 2) 
        )

    def forward(self, char_seq, lex_feats):
        # Char branch
        x = self.char_embed(char_seq).transpose(1, 2)
        x = [F.relu(conv(x)) for conv in self.convs]
        x = [F.max_pool1d(i, i.size(2)).squeeze(2) for i in x]
        char_out = torch.cat(x, 1)
        
        # Lexical branch
        lex_out = self.lexical_fc(lex_feats)
        
        # Kết hợp
        combined = torch.cat([char_out, lex_out], 1)
        return self.fc_final(combined)