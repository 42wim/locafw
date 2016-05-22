package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/soniah/gosnmp"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var cfg config
var lfw *locafw

type smap struct {
	sync.RWMutex
	m       map[string]string
	name    string
	counter int
	ctl     string
}

type locafw struct {
	List       map[string]*smap
	inputChan  chan string
	outputChan chan *smap
	conns      []*gosnmp.GoSNMP
}

type config struct {
	Web struct {
		Listen string
	}
	Controllers []string
	Ipset       struct {
		Name    string
		Timeout int
	}
	Acl []Acl
	sync.RWMutex
}

type Acl struct {
	Name  string
	Dstip []string
}

func (l *locafw) getList(g *gosnmp.GoSNMP, what string) *smap {
	var value string
	list := &smap{m: make(map[string]string), name: what}
	list.ctl = g.Target
	oid := "1.3.6.1.4.1.9.9.513.1.1.1.1.5"
	switch what {
	case "iplist":
		oid = "1.3.6.1.4.1.14179.2.1.4.1.2"
	case "ipaplist":
		oid = "1.3.6.1.4.1.14179.2.1.4.1.4"
	}
	fmt.Println("connecting", what, oid, g.Target)
	res, _ := g.BulkWalkAll(oid)
	for _, el := range res {
		ID := strings.Replace(el.Name, "."+oid+".", "", -1)
		mac := oidtohex(ID)
		if what == "iplist" {
			value = string(el.Value.(string))
		} else {
			// value is ip when "iplist" or apname when "aplist"
			value = string(el.Value.([]byte))
		}
		if what == "ipaplist" {
			apmac := hex.EncodeToString([]byte(value))
			if l.List["iplist"].m[mac] != "" && apmac != "000000000000" && mac != "" {
				list.m[l.List["aplist"].m[apmac]] = list.m[l.List["aplist"].m[apmac]] + " " + l.List["iplist"].m[mac]
			}
			continue
		}
		if value != "0.0.0.0" {
			list.m[mac] = value
		}
	}
	return list
}

func (l *locafw) handleInput() {
	for query := range l.inputChan {
		for _, g := range l.conns {
			l.outputChan <- l.getList(g, query)
		}
	}
	for _, g := range l.conns {
		g.Conn.Close()
	}
}

func (l *locafw) handleOutput() {
	myList := newList()
	for list := range l.outputChan {
		for k, v := range list.m {
			myList[list.name].m[k] = v
			if list.name == "aplist" {
				myList["ctllist"].m[v] = list.ctl
			}
		}
		myList[list.name].counter--
		if myList[list.name].counter == 0 {
			switch list.name {
			case "iplist":
				l.inputChan <- "ipaplist"
			case "aplist":
				l.List["ctllist"] = myList["ctllist"]
			}
			l.List[list.name] = myList[list.name]
			myList[list.name] = &smap{m: make(map[string]string), counter: len(cfg.Controllers)}
		}
	}
}

func newList() map[string]*smap {
	List := make(map[string]*smap)
	List["iplist"] = &smap{m: make(map[string]string), counter: len(cfg.Controllers)}
	List["aplist"] = &smap{m: make(map[string]string), counter: len(cfg.Controllers)}
	List["ipaplist"] = &smap{m: make(map[string]string), counter: len(cfg.Controllers)}
	List["ctllist"] = &smap{m: make(map[string]string), counter: len(cfg.Controllers)}
	return List
}

func NewLocafw() *locafw {
	List := newList()
	lfw := &locafw{List: List, inputChan: make(chan string), outputChan: make(chan *smap)}
	for _, target := range cfg.Controllers {
		g := &gosnmp.GoSNMP{Port: 161,
			Community: "public",
			Version:   gosnmp.Version2c,
			Timeout:   time.Duration(5) * time.Second,
			Retries:   3,
			Target:    target,
		}
		lfw.conns = append(lfw.conns, g)
		g.Connect()
	}
	return lfw
}

func main() {
	read_configuration("config.yaml")
	lfw = NewLocafw()
	go lfw.handleOutput()
	go lfw.handleInput()
	http.HandleFunc("/ip", HandleIp)
	http.HandleFunc("/ipset", HandleIpset)
	http.HandleFunc("/reload", HandleReload)
	go http.ListenAndServe(cfg.Web.Listen, nil)
	for {
		lfw.inputChan <- "aplist"
		lfw.inputChan <- "iplist"
		time.Sleep(time.Second * 10)
	}
}

func oidtohex(oid string) string {
	var res string
	o := strings.Fields(strings.Replace(oid, ".", " ", -1))
	for _, l := range o {
		i, _ := strconv.Atoi(l)
		res += fmt.Sprintf("%02x", i)
	}
	return res
}

func HandleReload(w http.ResponseWriter, r *http.Request) {
	read_configuration("config.yaml")
	w.Write([]byte("config reloaded."))
}

func HandleIp(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		ml := make(map[string][]string)
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		for k, v := range lfw.List["ipaplist"].m {
			ml[k] = strings.Fields(v)
		}
		if err := json.NewEncoder(w).Encode(ml); err != nil {
			log.Println(err)
		}
		return
	}
}

func HandleIpset(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		ml := make(map[string][]string)

		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		for k, v := range lfw.List["ipaplist"].m {
			ml[k] = strings.Fields(v)
		}
		for _, entry := range cfg.Acl {
			re := regexp.MustCompile(entry.Name)
			for k, srcip := range ml {
				if re.MatchString(k) {
					for _, ip := range srcip {
						for _, dstip := range entry.Dstip {
							str := "add " + cfg.Ipset.Name + " " + ip + "," + dstip + " " + strconv.Itoa(cfg.Ipset.Timeout) + "\n"
							w.Write([]byte(str))
						}
					}
				}
			}
		}
		return
	}
}

func read_configuration(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil
	}
	cfg.Lock()
	err = yaml.Unmarshal([]byte(data), &cfg)
	cfg.Unlock()
	if err != nil {
		return err
	}
	return nil
}
