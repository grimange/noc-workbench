package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"sync"
	"time"
)

// OwnApplication enforces the single active process assumption before trust or
// interrupted-run recovery. The dedicated session is never returned to a pool.
// Losing it cancels the application, so uncertain ownership cannot dispatch SSH.
func (s *Store) OwnApplication(ctx context.Context, cancel context.CancelFunc) (func(), error) {
	conn, e := pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig.Copy())
	if e != nil {
		return nil, ErrUnavailable
	}
	var acquired bool
	if e = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(110010,110011)`).Scan(&acquired); e != nil || !acquired {
		_ = conn.Close(context.Background())
		return nil, errors.New("another active application owns collection recovery and scheduling")
	}
	watch, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			select {
			case <-watch.Done():
				return
			case <-timer.C:
				ping, done := context.WithTimeout(watch, time.Second)
				err := conn.Ping(ping)
				done()
				if err != nil {
					if watch.Err() == nil {
						cancel()
					}
					return
				}
			}
		}
	}()
	return func() {
		stop()
		wg.Wait()
		closeCtx, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		_ = conn.Close(closeCtx)
	}, nil
}
