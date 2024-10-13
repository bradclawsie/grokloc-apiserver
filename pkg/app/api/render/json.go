package render

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func JSON(w http.ResponseWriter, logger *slog.Logger, data any) {
	bs, bsErr := json.Marshal(data)
	if bsErr != nil {
		logger.Error("marshal output json", "err", bsErr)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, wErr := w.Write(bs)
	if wErr != nil {
		logger.Error("response write", "err", wErr)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
}
