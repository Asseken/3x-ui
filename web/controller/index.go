package controller

import (
	"net/http"
	"sync"
	"time"

	"x-ui/logger"
	"x-ui/web/service"
	"x-ui/web/session"

	"github.com/gin-gonic/gin"
)

type LoginForm struct {
	Username    string `json:"username" form:"username"`
	Password    string `json:"password" form:"password"`
	LoginSecret string `json:"loginSecret" form:"loginSecret"`
}

type LoginAttempt struct {
	Timestamp   time.Time
	Count       int
	BannedUntil time.Time
}

type IndexController struct {
	BaseController

	settingService service.SettingService
	userService    service.UserService
	tgbot          service.Tgbot

	loginAttempts map[string]*LoginAttempt
	mu            sync.Mutex
}

func NewIndexController(g *gin.RouterGroup) *IndexController {
	a := &IndexController{
		loginAttempts: make(map[string]*LoginAttempt),
	}
	a.initRouter(g)
	return a
}

func (a *IndexController) initRouter(g *gin.RouterGroup) {
	g.GET("/", a.index)
	g.POST("/login", a.login)
	g.GET("/logout", a.logout)
	g.POST("/getSecretStatus", a.getSecretStatus)
}

func (a *IndexController) index(c *gin.Context) {
	if session.IsLogin(c) {
		c.Redirect(http.StatusTemporaryRedirect, "panel/")
		return
	}
	html(c, "login.html", "pages.login.title", nil)
}

func (a *IndexController) login(c *gin.Context) {
	var form LoginForm
	err := c.ShouldBind(&form)
	if err != nil {
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.invalidFormData"))
		return
	}
	if form.Username == "" {
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.emptyUsername"))
		return
	}
	if form.Password == "" {
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.emptyPassword"))
		return
	}

	ip := getRemoteIp(c)
	now := time.Now()

	a.mu.Lock()
	if attempt, exists := a.loginAttempts[ip]; exists {
		// Check if the IP is currently banned
		if now.Before(attempt.BannedUntil) {
			remainingTime := time.Until(attempt.BannedUntil).Seconds()
			a.mu.Unlock()
			logger.Warningf("IP %s is temporarily banned for %.0f seconds due to too many failed login attempts", ip, remainingTime)
			pureJsonMsg(c, http.StatusForbidden, false, "Too many failed login attempts. Try again later.")
			return
		}
		// Clean up old attempts if more than a minute has passed
		if now.Sub(attempt.Timestamp) > time.Minute {
			attempt.Count = 0
			attempt.Timestamp = now
		}
		// Increment attempt count
		attempt.Count++
	} else {
		a.loginAttempts[ip] = &LoginAttempt{Timestamp: now, Count: 1}
	}
	attempt := a.loginAttempts[ip]
	a.mu.Unlock()

	if attempt.Count > 3 {
		a.mu.Lock()
		attempt.BannedUntil = now.Add(3 * time.Minute) // Ban for 3 minutes
		a.mu.Unlock()
		logger.Warningf("IP %s is temporarily banned for 3 minutes due to too many failed login attempts", ip)
		pureJsonMsg(c, http.StatusForbidden, false, "Too many failed login attempts. Try again later.")
		return
	}

	user := a.userService.CheckUser(form.Username, form.Password, form.LoginSecret)
	timeStr := now.Format("2006-01-02 15:04:05")
	if user == nil {
		logger.Warningf("wrong username or password: \"%s\" \"%s\"", form.Username, form.Password)
		a.tgbot.UserLoginNotify(form.Username, ip, timeStr, 0)
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.wrongUsernameOrPassword"))
		return
	} else {
		logger.Infof("%s login success, Ip Address: %s\n", form.Username, ip)
		a.tgbot.UserLoginNotify(form.Username, ip, timeStr, 1)
	}

	sessionMaxAge, err := a.settingService.GetSessionMaxAge()
	if err != nil {
		logger.Warningf("Unable to get session's max age from DB")
	}

	if sessionMaxAge > 0 {
		err = session.SetMaxAge(c, sessionMaxAge*60)
		if err != nil {
			logger.Warningf("Unable to set session's max age")
		}
	}

	err = session.SetLoginUser(c, user)
	logger.Info("user", user.Id, "login success")
	jsonMsg(c, I18nWeb(c, "pages.login.toasts.successLogin"), err)
}

func (a *IndexController) logout(c *gin.Context) {
	user := session.GetLoginUser(c)
	if user != nil {
		logger.Info("user", user.Id, "logout")
	}
	session.ClearSession(c)
	c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path"))
}

func (a *IndexController) getSecretStatus(c *gin.Context) {
	status, err := a.settingService.GetSecretStatus()
	if err == nil {
		jsonObj(c, status, nil)
	}
}
